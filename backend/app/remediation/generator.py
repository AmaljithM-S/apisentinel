"""Remediation generator.

Two sources, in priority order:

1. A concrete fix produced by the reasoning layer for *this* endpoint (it has
   seen the actual code, so its patch references real variable names).
2. A curated, category-specific template with a working FastAPI snippet.

The templates are the safety net: they guarantee that every finding — including
one raised by Bandit or Semgrep with no model involvement, or raised when the
reasoning layer is offline — still reaches the developer with an actionable fix
rather than a bare rule id.
"""


from typing import Optional, Sequence, Tuple

from app.analysis_types import LayerFinding

TEMPLATES: dict[str, Tuple[str, str]] = {
    "API1": (
        "Load the object, then authorise it against the authenticated caller before "
        "returning it. Never trust an identifier taken from the path, query or body as "
        "proof of entitlement.",
        """@router.get("/orders/{order_id}", response_model=OrderOut)
def get_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    order = db.get(Order, order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    # Object-level authorisation: the caller must own the object.
    if order.owner_id != current_user.id and current_user.role != "admin":
        # 404 rather than 403 avoids confirming that the id exists.
        raise HTTPException(status_code=404, detail="Order not found")
    return order""",
    ),
    "API2": (
        "Require an authenticated principal through a dependency, and verify the token's "
        "signature, algorithm and expiry explicitly. Reject unsigned or 'none'-algorithm "
        "tokens outright.",
        """bearer = HTTPBearer(auto_error=False)

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        claims = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=["HS256"],   # pin the algorithm; never accept "none"
            options={"verify_signature": True, "verify_exp": True},
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.get(User, uuid.UUID(claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Account is not active")
    return user""",
    ),
    "API3": (
        "Declare an explicit response model listing only the properties the client is "
        "entitled to see, and let the framework serialise through it. Do not return ORM "
        "rows or dictionaries built from them.",
        """class UserPublic(BaseModel):
    id: int
    email: EmailStr
    display_name: str
    # password_hash, ssn, mfa_secret are deliberately absent.

    model_config = ConfigDict(from_attributes=True)

@router.get("/users/{user_id}", response_model=UserPublic)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Not found")
    return user  # serialised through UserPublic, extra fields dropped""",
    ),
    "API4": (
        "Bound every collection read and rate limit the endpoint. An unbounded query is a "
        "denial-of-service primitive that any caller can trigger.",
        """@router.get("/items", response_model=list[ItemOut])
@limiter.limit("60/minute")
def list_items(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    return db.query(Item).order_by(Item.id).offset(offset).limit(limit).all()""",
    ),
    "API5": (
        "Enforce the required role or scope in a dependency so the check cannot be "
        "forgotten in the handler body, and apply it to every route in the privileged "
        "router.",
        """def require_role(*roles: str):
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return current_user
    return dependency

admin_router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(require_role("admin"))],  # applies to every route below
)""",
    ),
    "API6": (
        "Enforce the stated business constraint in code, inside the same transaction that "
        "performs the operation, so it cannot be bypassed by concurrent requests.",
        """DAILY_LIMIT = Decimal("5000")
APPROVAL_THRESHOLD = Decimal("3000")

@router.post("/transfers", response_model=TransferOut)
def create_transfer(
    payload: TransferIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    with db.begin_nested():  # serialise the check with the write
        spent_today = db.query(func.coalesce(func.sum(Transfer.amount), 0)).filter(
            Transfer.user_id == current_user.id,
            Transfer.created_at >= date.today(),
        ).scalar()

        limit = DAILY_LIMIT if current_user.tier != "premium" else DAILY_LIMIT * 4
        if spent_today + payload.amount > limit:
            raise HTTPException(status_code=422, detail="Daily transfer limit exceeded")
        if payload.amount > APPROVAL_THRESHOLD and not payload.manager_approval_id:
            raise HTTPException(status_code=422, detail="Manager approval required")

        transfer = Transfer(user_id=current_user.id, **payload.model_dump())
        db.add(transfer)
    db.commit()
    return transfer""",
    ),
    "API7": (
        "Validate any caller-supplied URL against an allowlist of schemes and hosts, and "
        "resolve the host before fetching so a redirect cannot reach internal networks.",
        """ALLOWED_HOSTS = {"images.example.com", "cdn.example.com"}

def safe_fetch(raw_url: str) -> bytes:
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=422, detail="Unsupported URL scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=422, detail="Host is not allowed")
    address = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if address.is_private or address.is_loopback or address.is_link_local:
        raise HTTPException(status_code=422, detail="Host resolves to an internal address")
    with httpx.Client(timeout=10, follow_redirects=False) as client:
        return client.get(raw_url).content""",
    ),
    "API8": (
        "Drive every security-relevant setting from validated configuration that defaults "
        "to the safe value, and never enable debug output in a deployed environment.",
        """class Settings(BaseSettings):
    debug: bool = False                      # safe default
    cors_origins: list[str] = []              # no wildcard
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()

app = FastAPI(debug=settings.debug, docs_url="/docs" if settings.debug else None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,      # explicit origins, never "*" with credentials
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)""",
    ),
    "API9": (
        "Remove debug and internal routes from the deployed application, and keep the "
        "published specification in step with the routes that actually exist.",
        """if settings.debug:
    # Debug surface is registered only in local development builds.
    app.include_router(debug_router, prefix="/__debug", include_in_schema=False)""",
    ),
    "API10": (
        "Use bound parameters for every query, and validate and re-encode any data passed "
        "to a downstream system. Never build a statement by concatenating input.",
        """# Wrong: the query structure depends on caller input.
# db.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))

# Right: the value is bound, so it can never change the statement.
row = db.execute(
    text("SELECT id, email FROM users WHERE email = :email"),
    {"email": email},
).mappings().first()

# With the ORM, filters are parameterised for you:
user = db.query(User).filter(User.email == email).one_or_none()""",
    ),
}

GENERIC = (
    "Add the missing control to the endpoint and cover it with a regression test that "
    "asserts the request is rejected when the control does not hold.",
    "",
)


def generate_remediation(
    category: str,
    evidence: Sequence[LayerFinding],
    model_hint: Optional[str] = None,
) -> tuple[str, Optional[str]]:
    """Return ``(prose remediation, optional code snippet)``."""
    guidance, snippet = TEMPLATES.get(category, GENERIC)

    model_code: Optional[str] = None
    for finding in evidence:
        code = finding.detail.get("remediation_code") if finding.detail else None
        if code:
            model_code = str(code)
            break

    parts: list[str] = []
    if model_hint:
        parts.append(model_hint.strip())
    if guidance and guidance.strip() not in " ".join(parts):
        parts.append(guidance)

    business_rule = next((f.business_rule_ref for f in evidence if f.business_rule_ref), None)
    if business_rule:
        parts.append(
            f"This fix must enforce the stated requirement: “{business_rule}”. Enforce it "
            "server-side, in the same transaction as the operation it constrains."
        )

    return "\n\n".join(p for p in parts if p).strip(), (model_code or snippet or None)
