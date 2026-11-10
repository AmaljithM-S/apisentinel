"""APISentinel API application factory.

Wiring order matters: structured logging first (so startup problems are
readable), then middleware, then routers, then the error handlers that
guarantee no unhandled exception ever reaches the client as a stack trace.
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api import auth, findings, health, projects, reports, runtime, scans
from app.config import settings
from app.logging_config import configure_logging
from app.rate_limit import limiter

configure_logging()
logger = logging.getLogger("apisentinel")

app = FastAPI(
    title="APISentinel",
    version="1.0.0",
    description=(
        "Hybrid multi-layer API security framework: static analysis, contextual "
        "reasoning, and runtime differential validation fused into one risk model."
    ),
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.environment == "development" else None,
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    # Credentials travel in the Authorization header, not cookies, so a wildcard
    # origin cannot be abused to replay a browser session.
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "request failed", extra={"request_id": request_id, "path": request.url.path}
        )
        raise
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    # Defence in depth for the served API surface itself.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    logger.info(
        "%s %s -> %s in %sms",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
        extra={"request_id": request_id},
    )
    return response


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        {"detail": "Too many requests. Slow down and try again shortly."},
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": "60"},
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        {
            "detail": "The request payload was rejected.",
            "errors": [
                {"field": ".".join(str(p) for p in err["loc"][1:]), "message": err["msg"]}
                for err in exc.errors()
            ],
        },
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    # The details are logged server-side; the client gets no internals.
    logger.exception("unhandled error on %s", request.url.path)
    return JSONResponse(
        {"detail": "Something went wrong while processing that request."},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


for router in (
    health.router,
    auth.router,
    projects.router,
    scans.router,
    findings.router,
    runtime.router,
    reports.router,
):
    app.include_router(router)


@app.on_event("startup")
def announce() -> None:
    logger.info(
        "APISentinel started (environment=%s, llm=%s, zap=%s, allowlist=%s)",
        settings.environment,
        settings.llm_provider,
        bool(settings.zap_base_url),
        ",".join(settings.allowlisted_targets),
    )
    if settings.environment == "production" and settings.jwt_secret == "change-me-in-production":
        logger.error(
            "JWT_SECRET is still the default value. Set a strong secret before exposing this "
            "service — every issued token can otherwise be forged."
        )
