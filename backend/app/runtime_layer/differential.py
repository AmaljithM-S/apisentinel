"""Differential authorization testing (Listing 7.1 of the report).

The core idea: static analysis and an LLM can both *suspect* that an endpoint
never checks object ownership, but only a running system can prove it. So for a
candidate BOLA finding on ``GET /users/{id}/profile`` the tester

1. authenticates as user A and requests A's own resource (control request),
2. re-issues the request for user B's identifier with A's token (probe),

and compares the two responses. A 200 on the probe that returns a body
materially different from the control is a confirmed authorization failure — the
token of one user retrieved another user's object. A 401/403/404 refutes it.

Broken-authentication candidates are tested by removing the credential
entirely: an endpoint that answers 200 with no token is unauthenticated in fact,
not just in appearance.

Every request is bounded by a timeout, the target is allowlist-checked, and the
tester never mutates state on write endpoints — probes are read-only by design.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings
from app.runtime_layer.safety import assert_target_allowed

SAFE_PROBE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class TestAccount:
    label: str
    token: Optional[str] = None
    object_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProbeResult:
    name: str
    target_url: str
    outcome: str  # confirmed | refuted | inconclusive | skipped
    confirmed: bool
    confidence: float
    detail: Dict[str, Any]


class RuntimeTester:
    def __init__(self, base_url: str, credentials: Optional[Dict[str, Any]] = None) -> None:
        self.base_url = assert_target_allowed(base_url)
        self.credentials = credentials or {}
        self.accounts: List[TestAccount] = []
        self.warnings: List[str] = []
        self._client = httpx.Client(
            timeout=settings.runtime_timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "APISentinel-RuntimeValidator/1.0"},
        )

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "RuntimeTester":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- authentication ----------------------------------------------------
    def authenticate(self) -> bool:
        """Log in the two configured test users.

        ``credentials`` shape (all optional except users):
            {"login_path": "/auth/login",
             "login_style": "json" | "form",
             "token_field": "access_token",
             "identifier_field": "username",   # the JSON/form key the login
                                                # endpoint expects for the
                                                # identifier; e.g. "email" for
                                                # targets that log in by email
             "users": [{"label": "A", "username": "...", "password": "...",
                        "object_id": "1"}, {...}]}

        Each user entry may give the identifier as ``username`` or ``email``
        (either is accepted on read, since both are common); which JSON key is
        actually *sent* to the login endpoint is controlled separately by
        ``identifier_field``, because the two are not always the same thing — a
        target can accept an email address as the value of a field literally
        called ``username``, or vice versa. A user entry may also give
        ``owned_ids`` (a list) instead of a single ``object_id``; the first
        entry of ``owned_ids`` is used when ``object_id`` is absent.
        """
        users = self.credentials.get("users") or []
        if len(users) < 1:
            self.warnings.append(
                "Runtime validation needs at least one test account. Provide two accounts "
                "(A and B) to enable differential authorization testing."
            )
            return False

        login_path = str(self.credentials.get("login_path") or "/auth/login")
        style = str(self.credentials.get("login_style") or "json").lower()
        token_field = str(self.credentials.get("token_field") or "access_token")
        identifier_field = str(self.credentials.get("identifier_field") or "username")

        for index, raw in enumerate(users[:2]):
            identifier = raw.get("username") or raw.get("email")
            object_id = raw.get("object_id")
            if object_id is None:
                owned = raw.get("owned_ids")
                if isinstance(owned, list) and owned:
                    object_id = owned[0]
            account = TestAccount(
                label=str(raw.get("label") or f"user{index + 1}"),
                username=identifier,
                password=raw.get("password"),
                object_id=str(object_id) if object_id is not None else None,
                token=raw.get("token"),
            )
            if account.token:
                self.accounts.append(account)
                continue
            if not account.username or not account.password:
                self.warnings.append(
                    f"Account '{account.label}' has neither a token nor a username/email and password."
                )
                continue
            payload = {identifier_field: account.username, "password": account.password}
            try:
                if style == "form":
                    response = self._client.post(self._url(login_path), data=payload)
                else:
                    response = self._client.post(self._url(login_path), json=payload)
            except httpx.HTTPError as exc:
                self.warnings.append(f"Login request failed for '{account.label}': {exc}")
                continue
            if response.status_code >= 400:
                self.warnings.append(
                    f"Login for '{account.label}' returned {response.status_code} at "
                    f"{login_path}. Check login_path/login_style."
                )
                continue
            try:
                token = response.json().get(token_field)
            except ValueError:
                token = None
            if not token:
                self.warnings.append(
                    f"Login response for '{account.label}' has no '{token_field}' field."
                )
                continue
            account.token = str(token)
            self.accounts.append(account)

        return len(self.accounts) >= 1

    # -- probes ------------------------------------------------------------
    def probe_bola(self, method: str, path: str) -> ProbeResult:
        name = f"Differential authorization: {method} {path}"
        if method.upper() not in SAFE_PROBE_METHODS:
            return ProbeResult(
                name,
                self._url(path),
                "skipped",
                False,
                0.0,
                {
                    "reason": (
                        "Only read-only methods are probed automatically; probing a "
                        "state-changing method could damage the target."
                    )
                },
            )
        if len(self.accounts) < 2:
            return ProbeResult(
                name,
                self._url(path),
                "skipped",
                False,
                0.0,
                {"reason": "Two authenticated test accounts are required for a differential test."},
            )

        actor, victim = self.accounts[0], self.accounts[1]
        if not actor.object_id or not victim.object_id:
            return ProbeResult(
                name,
                self._url(path),
                "skipped",
                False,
                0.0,
                {"reason": "Both test accounts need an object_id to substitute into the path."},
            )

        control_url = self._url(self._substitute(path, actor.object_id))
        probe_url = self._url(self._substitute(path, victim.object_id))

        control = self._request(method, control_url, actor.token)
        probe = self._request(method, probe_url, actor.token)
        victim_view = self._request(method, probe_url, victim.token)

        detail: Dict[str, Any] = {
            "control_request": {
                "url": control_url,
                "as": actor.label,
                "status": control.get("status"),
            },
            "probe_request": {
                "url": probe_url,
                "as": f"{actor.label} token requesting {victim.label} object",
                "status": probe.get("status"),
            },
            "victim_baseline": {"url": probe_url, "as": victim.label, "status": victim_view.get("status")},
            "probe_body_excerpt": probe.get("body", "")[:600],
        }

        if control.get("error") or probe.get("error"):
            detail["error"] = control.get("error") or probe.get("error")
            return ProbeResult(name, probe_url, "inconclusive", False, 0.0, detail)

        if probe.get("status") in (401, 403):
            detail["conclusion"] = (
                f"The target rejected the cross-account request with {probe['status']}, so "
                "object-level authorization is enforced at runtime."
            )
            return ProbeResult(name, probe_url, "refuted", False, 0.95, detail)

        if probe.get("status") == 404 and control.get("status") == 200:
            detail["conclusion"] = (
                "The cross-account request returned 404 while the caller's own object "
                "returned 200. This is consistent with ownership-scoped lookup."
            )
            return ProbeResult(name, probe_url, "refuted", False, 0.8, detail)

        if probe.get("status") == 200:
            differs = probe.get("body") != control.get("body")
            matches_victim = (
                victim_view.get("status") == 200 and probe.get("body") == victim_view.get("body")
            )
            if matches_victim:
                detail["conclusion"] = (
                    f"{actor.label}'s token retrieved a response byte-identical to what "
                    f"{victim.label} sees for their own object. Cross-account object access is "
                    "confirmed at runtime."
                )
                return ProbeResult(name, probe_url, "confirmed", True, 0.98, detail)
            if differs:
                detail["conclusion"] = (
                    f"{actor.label}'s token received 200 with a body different from their own "
                    f"object for {victim.label}'s identifier, indicating another user's data "
                    "was returned."
                )
                return ProbeResult(name, probe_url, "confirmed", True, 0.95, detail)
            detail["conclusion"] = (
                "The cross-account request returned 200 but with the caller's own data, which "
                "suggests the identifier is ignored rather than authorised."
            )
            return ProbeResult(name, probe_url, "inconclusive", False, 0.5, detail)

        detail["conclusion"] = f"Unexpected status {probe.get('status')} on the cross-account probe."
        return ProbeResult(name, probe_url, "inconclusive", False, 0.3, detail)

    def probe_missing_auth(self, method: str, path: str) -> ProbeResult:
        name = f"Unauthenticated access check: {method} {path}"
        if method.upper() not in SAFE_PROBE_METHODS:
            return ProbeResult(
                name,
                self._url(path),
                "skipped",
                False,
                0.0,
                {"reason": "State-changing methods are not probed automatically."},
            )
        sample_id = next((a.object_id for a in self.accounts if a.object_id), "1")
        url = self._url(self._substitute(path, sample_id))
        anonymous = self._request(method, url, None)
        detail: Dict[str, Any] = {
            "anonymous_request": {"url": url, "status": anonymous.get("status")},
            "body_excerpt": anonymous.get("body", "")[:600],
        }
        if anonymous.get("error"):
            detail["error"] = anonymous["error"]
            return ProbeResult(name, url, "inconclusive", False, 0.0, detail)
        if anonymous.get("status") in (401, 403):
            detail["conclusion"] = (
                f"The endpoint rejected an unauthenticated request with {anonymous['status']}; "
                "authentication is enforced at runtime."
            )
            return ProbeResult(name, url, "refuted", False, 0.95, detail)
        if anonymous.get("status") == 200:
            detail["conclusion"] = (
                "The endpoint returned 200 to a request carrying no credentials at all: it is "
                "effectively public."
            )
            return ProbeResult(name, url, "confirmed", True, 0.97, detail)
        detail["conclusion"] = f"Unexpected status {anonymous.get('status')}."
        return ProbeResult(name, url, "inconclusive", False, 0.3, detail)

    def probe_sensitive_fields(self, method: str, path: str) -> ProbeResult:
        """Confirm excessive data exposure by inspecting a real response body."""
        name = f"Sensitive field exposure check: {method} {path}"
        if method.upper() not in SAFE_PROBE_METHODS:
            return ProbeResult(name, self._url(path), "skipped", False, 0.0, {"reason": "Read-only probes only."})
        actor = self.accounts[0] if self.accounts else None
        sample_id = (actor.object_id if actor else None) or "1"
        url = self._url(self._substitute(path, sample_id))
        response = self._request(method, url, actor.token if actor else None)
        detail: Dict[str, Any] = {"url": url, "status": response.get("status")}
        if response.get("error") or response.get("status") != 200:
            detail["reason"] = response.get("error") or f"status {response.get('status')}"
            return ProbeResult(name, url, "inconclusive", False, 0.0, detail)

        body = (response.get("body") or "").lower()
        leaked = [
            term
            for term in (
                "password",
                "password_hash",
                "hashed_password",
                "ssn",
                "national_id",
                "credit_card",
                "card_number",
                "cvv",
                "api_key",
                "secret",
                "mfa_secret",
            )
            if f'"{term}"' in body
        ]
        detail["leaked_fields"] = leaked
        detail["body_excerpt"] = (response.get("body") or "")[:600]
        if leaked:
            detail["conclusion"] = (
                "The live response body contains sensitive field name(s): "
                + ", ".join(leaked)
                + ". Excessive data exposure is confirmed against the running API."
            )
            return ProbeResult(name, url, "confirmed", True, 0.96, detail)
        detail["conclusion"] = "No sensitive field names were present in the live response body."
        return ProbeResult(name, url, "refuted", False, 0.85, detail)

    # -- helpers -----------------------------------------------------------
    def _request(self, method: str, url: str, token: Optional[str]) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            response = self._client.request(method.upper(), url, headers=headers)
        except httpx.HTTPError as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
        return {
            "status": response.status_code,
            "body": response.text[:20000],
            "content_type": response.headers.get("content-type", ""),
        }

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    @staticmethod
    def _substitute(path: str, value: str) -> str:
        out: List[str] = []
        depth = 0
        for char in path:
            if char == "{":
                depth += 1
                if depth == 1:
                    out.append(value)
                continue
            if char == "}":
                depth -= 1
                continue
            if depth == 0:
                out.append(char)
        return "".join(out)


def measure(fn, *args, **kwargs) -> tuple[Any, float]:
    started = time.monotonic()
    value = fn(*args, **kwargs)
    return value, time.monotonic() - started
