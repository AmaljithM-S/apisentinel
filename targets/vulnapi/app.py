"""Deliberately vulnerable FastAPI service — the evaluation target.

DO NOT DEPLOY. Every flaw here is intentional and labelled in
``datasets/ground_truth.yml``. It exists so the framework's five layers can be
exercised end to end and measured against a known answer key, including the
runtime differential layer, which needs a live API to probe.

Coverage:
  API1  BOLA                     /orders/{id}, /invoices/{id}
  API2  Broken authentication    /profile/{user_id}, /login (no lockout)
  API3  Excessive data exposure  /users/{id}, /users
  API4  Unrestricted consumption /search (unbounded)
  API5  BFLA                     /admin/users, /admin/promote
  API6  Business-logic flaw      /transfers (limit not enforced)
  API7  SSRF                     /fetch-avatar
  API8  Misconfiguration         debug=True, wildcard CORS with credentials
  API9  Improper inventory       /internal/debug/config
  API10 Injection                /users/search-by-email (raw SQL)

Endpoints that are safe by construction are included on purpose: a framework
that flags them is producing false positives, and the harness measures that.
"""

from __future__ import annotations

import os
import sqlite3
from decimal import Decimal
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_PATH = os.environ.get("VULNAPI_DB", "/tmp/vulnapi.db")

# VULNERABLE (API8): debug mode on, docs exposed, wildcard CORS with credentials.
app = FastAPI(title="VulnShop API", debug=True)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# VULNERABLE (API8/API2): a hardcoded, guessable signing secret.
SECRET_KEY = "supersecret123"


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS orders;
            DROP TABLE IF EXISTS invoices;
            DROP TABLE IF EXISTS transfers;

            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email TEXT, password TEXT, full_name TEXT,
                role TEXT, tier TEXT, ssn TEXT, mfa_secret TEXT, balance REAL
            );
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY, owner_id INTEGER, item TEXT, total REAL, card_last4 TEXT
            );
            CREATE TABLE invoices (
                id INTEGER PRIMARY KEY, owner_id INTEGER, amount REAL, tax_id TEXT
            );
            CREATE TABLE transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount REAL, note TEXT
            );

            INSERT INTO users VALUES
              (1,'alice@vulnshop.test','alice-password','Alice Adams','user','standard','111-22-3333','JBSWY3DPEHPK3PXP',4200.0),
              (2,'bob@vulnshop.test','bob-password','Bob Brown','user','standard','444-55-6666','KRSXG5CTMVRXEZLU',150.0),
              (3,'root@vulnshop.test','admin-password','Root Admin','admin','premium','777-88-9999','MFRGGZDFMZTWQ2LK',99000.0);

            INSERT INTO orders VALUES
              (1001,1,'Mechanical keyboard',180.0,'4242'),
              (1002,2,'Noise-cancelling headphones',320.0,'1881'),
              (1003,3,'Server rack',2400.0,'9004');

            INSERT INTO invoices VALUES
              (5001,1,180.0,'GB-TAX-1'),(5002,2,320.0,'GB-TAX-2');
            """
        )


init_db()


# --------------------------------------------------------------------------- auth
class LoginIn(BaseModel):
    email: str
    password: str


def issue_token(user: sqlite3.Row) -> str:
    # VULNERABLE (API2): an unsigned, self-describing token. Anyone can mint one.
    return f"user-{user['id']}-{user['role']}"


def current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """VULNERABLE (API2): the token is parsed, never verified."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    parts = token.split("-")
    if len(parts) < 3 or parts[0] != "user":
        raise HTTPException(status_code=401, detail="Malformed token")
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (parts[1],)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Unknown user")
    return dict(row)


@app.post("/login")
def login(payload: LoginIn):
    """VULNERABLE (API2): plaintext password comparison, no lockout, no rate limit."""
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? AND password = ?",
            (payload.email, payload.password),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Bad credentials")
    return {"access_token": issue_token(row), "token_type": "bearer"}


# --------------------------------------------------------------------- API1 BOLA
@app.get("/orders/{order_id}")
def get_order(order_id: int, user: Dict[str, Any] = Depends(current_user)):
    """VULNERABLE (API1): authenticated but never checks ownership."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return dict(row)


@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, user: Dict[str, Any] = Depends(current_user)):
    """VULNERABLE (API1 + API3): other users' invoices, including tax identifiers."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return dict(row)


@app.get("/my/orders")
def my_orders(user: Dict[str, Any] = Depends(current_user)):
    """SAFE: scoped to the caller. Flagging this is a false positive."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, item, total FROM orders WHERE owner_id = ? LIMIT 100", (user["id"],)
        ).fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------- API2 broken auth
@app.get("/profile/{user_id}")
def get_profile(user_id: int):
    """VULNERABLE (API2 + API3): no authentication at all on personal data."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    return dict(row)


# ------------------------------------------------- API3 excessive data exposure
@app.get("/users/{user_id}")
def get_user(user_id: int, user: Dict[str, Any] = Depends(current_user)):
    """VULNERABLE (API3): returns the whole row — password, SSN, MFA secret."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    return dict(row)


@app.get("/users")
def list_users(user: Dict[str, Any] = Depends(current_user)):
    """VULNERABLE (API3 + API4): every column of every row, unpaginated."""
    with connect() as conn:
        rows = conn.execute("SELECT * FROM users").fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------- API4 unrestricted resource usage
@app.get("/search")
def search(q: str = Query(default=""), limit: int = Query(default=100000)):
    """VULNERABLE (API4): caller-controlled unbounded limit, no rate limiting."""
    with connect() as conn:
        rows = conn.execute(
            f"SELECT id, item FROM orders WHERE item LIKE '%{q}%' LIMIT {limit}"  # noqa: S608
        ).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------- API5 BFLA
@app.get("/admin/users")
def admin_list_users(user: Dict[str, Any] = Depends(current_user)):
    """VULNERABLE (API5): an admin route with no role check."""
    with connect() as conn:
        rows = conn.execute("SELECT id, email, role, balance FROM users").fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/promote")
def admin_promote(user_id: int, user: Dict[str, Any] = Depends(current_user)):
    """VULNERABLE (API5): privilege escalation available to any authenticated user."""
    with connect() as conn:
        conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
        conn.commit()
    return {"promoted": user_id}


@app.get("/admin/audit-log")
def admin_audit_log(user: Dict[str, Any] = Depends(current_user)):
    """SAFE: the role check is present. Flagging this is a false positive."""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return {"entries": []}


# ----------------------------------------------------- API6 business-logic flaw
class TransferIn(BaseModel):
    amount: float
    note: str = ""


@app.post("/transfers")
def create_transfer(payload: TransferIn, user: Dict[str, Any] = Depends(current_user)):
    """VULNERABLE (API6).

    The documented rules are: standard accounts may transfer at most 5000 per
    day, and any transfer above 3000 requires manager approval. Neither is
    enforced, and the amount is not even checked for a negative value — so a
    negative transfer credits the account.
    """
    with connect() as conn:
        conn.execute(
            "INSERT INTO transfers (user_id, amount, note) VALUES (?, ?, ?)",
            (user["id"], payload.amount, payload.note),
        )
        conn.execute(
            "UPDATE users SET balance = balance - ? WHERE id = ?", (payload.amount, user["id"])
        )
        conn.commit()
    return {"transferred": payload.amount, "note": payload.note}


# --------------------------------------------------------------------- API7 SSRF
@app.get("/fetch-avatar")
def fetch_avatar(url: str):
    """VULNERABLE (API7): fetches any caller-supplied URL, including internal hosts."""
    with httpx.Client(timeout=5, follow_redirects=True) as client:
        response = client.get(url)
    return {"status": response.status_code, "body": response.text[:2000]}


# ------------------------------------------------ API9 improper inventory mgmt
@app.get("/internal/debug/config")
def debug_config():
    """VULNERABLE (API9 + API8): an undocumented debug route leaking configuration."""
    return {
        "secret_key": SECRET_KEY,
        "db_path": DB_PATH,
        "debug": True,
        "env": {k: v for k, v in os.environ.items() if "PATH" not in k},
    }


# ---------------------------------------------------------------- API10 injection
@app.get("/users/search-by-email")
def search_by_email(email: str, user: Dict[str, Any] = Depends(current_user)):
    """VULNERABLE (API10): the query is built by string concatenation."""
    query = f"SELECT id, email, full_name FROM users WHERE email = '{email}'"  # noqa: S608
    with connect() as conn:
        rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]


@app.get("/orders/by-item")
def orders_by_item(item: str, user: Dict[str, Any] = Depends(current_user)):
    """SAFE: parameterised query. Flagging this is a false positive."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, item FROM orders WHERE item = ? LIMIT 50", (item,)
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}
