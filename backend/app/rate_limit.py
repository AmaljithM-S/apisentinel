"""
Rate limiting utilities.

Important: Decorators must preserve endpoint signatures, otherwise FastAPI
can mis-detect body/query parameters and raise 422 validation errors.
"""

from __future__ import annotations

import inspect
from functools import wraps

from slowapi import Limiter
from slowapi.util import get_remote_address


class SignaturePreservingLimiter(Limiter):
    """Limiter that preserves endpoint signature for FastAPI."""

    def limit(self, limit_value: str, *args, **kwargs):
        base_decorator = super().limit(limit_value, *args, **kwargs)

        def decorator(func):
            wrapped = base_decorator(func)

            # Preserve metadata + make inspect.signature() resolve to the original.
            wrapped = wraps(func)(wrapped)
            wrapped.__signature__ = inspect.signature(func)  # type: ignore[attr-defined]
            return wrapped

        return decorator


# Exported limiter used across the app
limiter = SignaturePreservingLimiter(key_func=get_remote_address)
