"""OWASP ZAP integration over the ZAP REST API.

ZAP contributes what a hand-rolled HTTP client cannot: a maintained active-scan
rule set covering transport, header, and injection classes of issue, run against
the live target. It complements — rather than replaces — the differential
authorization tests, which encode application-specific ownership semantics ZAP
has no way to know.

ZAP is optional. When it is not configured or not reachable the layer degrades
to differential testing only and says so, instead of failing the scan.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import httpx

from app.analysis_types import LayerFinding
from app.config import settings
from app.owasp import normalise_category

_RISK_SEVERITY = {"informational": "low", "low": "low", "medium": "medium", "high": "high"}

# ZAP alert names mapped onto the OWASP API taxonomy where the mapping is
# unambiguous; anything else lands on API8 via normalise_category.
_ALERT_CATEGORY = {
    "sql injection": "API10",
    "remote os command injection": "API10",
    "cross site scripting": "API10",
    "path traversal": "API10",
    "server side request forgery": "API7",
    "cors misconfiguration": "API8",
    "content security policy": "API8",
    "cookie without secure flag": "API8",
    "information disclosure": "API3",
    "session id in url rewrite": "API2",
    "authentication request identified": "API2",
}


class ZapClient:
    def __init__(self) -> None:
        self.base_url = settings.zap_base_url.rstrip("/")
        self.api_key = settings.zap_api_key

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    def available(self) -> bool:
        if not self.configured:
            return False
        try:
            with httpx.Client(timeout=5) as client:
                response = client.get(f"{self.base_url}/JSON/core/view/version/", params=self._params())
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    def _params(self, **extra: Any) -> Dict[str, Any]:
        params = {"apikey": self.api_key} if self.api_key else {}
        params.update({k: v for k, v in extra.items() if v is not None})
        return params

    def passive_scan(self, target_url: str, timeout_seconds: int = 120) -> List[LayerFinding]:
        """Access the target through ZAP's proxy history and read passive alerts.

        A passive scan is used by default because it issues no attack traffic of
        its own: ZAP only inspects the requests the framework already makes.
        """
        if not self.available():
            return []
        with httpx.Client(timeout=30) as client:
            try:
                client.get(
                    f"{self.base_url}/JSON/core/action/accessUrl/",
                    params=self._params(url=target_url, followRedirects="false"),
                )
            except httpx.HTTPError:
                return []

            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                try:
                    status = client.get(
                        f"{self.base_url}/JSON/pscan/view/recordsToScan/", params=self._params()
                    ).json()
                except (httpx.HTTPError, ValueError):
                    break
                if str(status.get("recordsToScan", "0")) == "0":
                    break
                time.sleep(1)

            return self._alerts_for(target_url, client)

    def spider(
        self, target_url: str, *, max_children: int = 20, timeout_seconds: int = 180
    ) -> Dict[str, Any]:
        """Drive ZAP's traditional (link-following) spider against the target.

        This widens *discovery* — ZAP finds URLs our own crawler missed, which
        then also benefit from the passive/active alerts below — it does not by
        itself raise any findings. Read-only in the sense that it only follows
        links; it does not submit forms or run attack payloads.
        """
        if not self.available():
            return {"ok": False, "reason": "ZAP is not reachable"}
        with httpx.Client(timeout=30) as client:
            try:
                started = client.get(
                    f"{self.base_url}/JSON/spider/action/scan/",
                    params=self._params(url=target_url, maxChildren=max_children, recurse="true"),
                ).json()
            except (httpx.HTTPError, ValueError) as exc:
                return {"ok": False, "reason": str(exc)}
            scan_id = started.get("scan")
            deadline = time.monotonic() + timeout_seconds
            progress = 0
            while time.monotonic() < deadline:
                try:
                    status = client.get(
                        f"{self.base_url}/JSON/spider/view/status/",
                        params=self._params(scanId=scan_id),
                    ).json()
                    progress = int(status.get("status", 0))
                except (httpx.HTTPError, ValueError, TypeError):
                    break
                if progress >= 100:
                    break
                time.sleep(1)
        return {"ok": True, "scan_id": scan_id, "progress": progress}

    def active_scan(
        self, target_url: str, *, timeout_seconds: int = 900
    ) -> List[LayerFinding]:
        """Run ZAP's Active Scan: it sends real attack payloads at the target.

        Unlike every other method on this client, this one is genuinely
        intrusive (SQLi/XSS probes, timing attacks, and so on) and must only be
        reached when BOTH the operator has set ``ZAP_ENABLE_ACTIVE_SCAN=true``
        and the specific scan explicitly opted in — both checks are the
        caller's responsibility (``web_layer.pipeline``), enforced again here as
        a second line of defence.
        """
        from app.config import settings as _settings  # local import avoids a cycle

        if not _settings.zap_enable_active_scan:
            return []
        if not self.available():
            return []
        with httpx.Client(timeout=30) as client:
            try:
                started = client.get(
                    f"{self.base_url}/JSON/ascan/action/scan/",
                    params=self._params(url=target_url, recurse="true", inScopeOnly="false"),
                ).json()
            except (httpx.HTTPError, ValueError):
                return []
            scan_id = started.get("scan")
            if scan_id is None:
                return []
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                try:
                    status = client.get(
                        f"{self.base_url}/JSON/ascan/view/status/",
                        params=self._params(scanId=scan_id),
                    ).json()
                    if int(status.get("status", 0)) >= 100:
                        break
                except (httpx.HTTPError, ValueError, TypeError):
                    break
                time.sleep(2)
            findings = self._alerts_for(target_url, client)
        for finding in findings:
            finding.tool = "zap-active-scan"
            finding.detail["scan_mode"] = "active"
        return findings

    def _alerts_for(self, target_url: str, client: "httpx.Client") -> List[LayerFinding]:
        try:
            payload = client.get(
                f"{self.base_url}/JSON/alert/view/alerts/",
                params=self._params(baseurl=target_url, start=0, count=200),
            ).json()
        except (httpx.HTTPError, ValueError):
            return []

        findings: List[LayerFinding] = []
        for alert in payload.get("alerts", []):
            name = str(alert.get("alert", "")).strip()
            lowered = name.lower()
            category: Optional[str] = None
            for needle, cid in _ALERT_CATEGORY.items():
                if needle in lowered:
                    category = cid
                    break
            findings.append(
                LayerFinding(
                    source="runtime",
                    tool="zap",
                    category=category or normalise_category(name),
                    title=f"ZAP: {name}"[:280],
                    description=str(alert.get("description", ""))[:4000],
                    severity=_RISK_SEVERITY.get(str(alert.get("risk", "")).lower(), "medium"),
                    # A ZAP alert is live evidence, but a passive alert is not proof
                    # of exploitability, so it sits below a differential confirmation.
                    confidence=0.8 if str(alert.get("confidence", "")).lower() == "high" else 0.7,
                    detail={
                        "url": alert.get("url"),
                        "evidence": alert.get("evidence"),
                        "cweid": alert.get("cweid"),
                        "wascid": alert.get("wascid"),
                        "risk": alert.get("risk"),
                        "zap_confidence": alert.get("confidence"),
                    },
                    remediation_hint=str(alert.get("solution", ""))[:2000] or None,
                    confirmed=False,
                )
            )
        return findings
