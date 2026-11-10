"""Unit tests for the deterministic core: taxonomy, parser, fusion, scoring, safety."""

import os

os.environ.setdefault("DATABASE_URL", "sqlite://")
# Deliberately NOT os.environ.setdefault("RUNTIME_TARGET_ALLOWLIST", ...) here:
# app.config.settings is a singleton built once, on first import, by whichever
# test module happens to trigger it first — setting the *environment variable*
# at this module's top would silently become that singleton's permanent
# initial value for the rest of the whole test session (every file), not just
# a default for this file's own test. test_runtime_allowlist below sets
# settings.runtime_target_allowlist directly instead, scoped to itself with a
# proper restore, which is the only way to change it without that side effect.

import pytest

from app.analysis_types import LayerFinding
from app.owasp import normalise_category
from app.parser.fastapi_parser import parse_file
from app.risk_engine.fusion import fuse_findings
from app.risk_engine.scoring import risk_score
from app.runtime_layer.safety import is_target_allowed

SOURCE = '''
from fastapi import FastAPI, Depends, APIRouter
app = FastAPI()
router = APIRouter(prefix="/v1")

def get_user(): ...

@app.get("/orders/{order_id}")
def read_order(order_id: int, user=Depends(get_user)):
    return {}

@router.delete("/admin/users/{uid}")
def delete_user(uid: int):
    return {}

app.include_router(router)
'''


def test_normalise_category_aliases():
    assert normalise_category("API1") == "API1"
    assert normalise_category("API1:2023 Broken Object Level Authorization").startswith("API1")


def test_parser_extracts_routes_prefix_and_auth():
    eps = {(e.method, e.path): e for e in parse_file("app.py", SOURCE)}
    assert ("GET", "/orders/{order_id}") in eps
    assert any(p.endswith("/admin/users/{uid}") for _, p in eps)
    assert eps[("GET", "/orders/{order_id}")].auth_dependencies


def _lf(source, conf, confirmed=False, desc="x"):
    return LayerFinding(source=source, tool="t", category="API1", title="BOLA", description=desc,
                        severity="high", confidence=conf, endpoint_key="GET /orders/{order_id}", confirmed=confirmed)


def test_fusion_noisy_or_corroboration_capped():
    fused = fuse_findings([_lf("static", 0.7), _lf("llm", 0.8)])
    assert len(fused) == 1
    assert 0.8 < fused[0].confidence <= 0.94


def test_fusion_llm_only_capped():
    fused = fuse_findings([_lf("llm", 0.99)])
    assert fused[0].confidence <= 0.85


def test_runtime_confirmation_pins_high_confidence():
    fused = fuse_findings([_lf("llm", 0.6), _lf("runtime", 0.95, confirmed=True)])
    assert fused[0].confidence >= 0.95


def test_risk_score_monotonic():
    assert risk_score("critical", 0.9) > risk_score("low", 0.9)
    assert risk_score("high", 0.9, runtime_confirmed=True) > risk_score("high", 0.9)


@pytest.mark.parametrize("url,ok", [("http://vulnapi:8001", True), ("http://evil.example.com", False)])
def test_runtime_allowlist(url, ok):
    # Set directly on the already-constructed settings singleton rather than
    # relying on the os.environ.setdefault() above, which only has an effect
    # if this module happens to be imported before anything else constructs
    # `app.config.settings` — an import-order assumption that does not hold
    # once other test files also import the app. Restored afterwards so this
    # test cannot change the allowlist for tests that run after it.
    from app.config import settings

    previous = settings.runtime_target_allowlist
    settings.runtime_target_allowlist = "http://vulnapi:8001"
    try:
        assert is_target_allowed(url) is ok
    finally:
        settings.runtime_target_allowlist = previous
