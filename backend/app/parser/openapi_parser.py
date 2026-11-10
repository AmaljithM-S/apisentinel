"""OpenAPI / Swagger specification ingestion.

The spec is a second, independent view of the same API. It supplies the human
intent (summary, description, declared security scheme) that source code often
omits, which materially improves the LLM layer's inference of purpose, and it
reveals endpoints documented but absent from the uploaded source.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence

import yaml

from app.parser.fastapi_parser import ParsedEndpoint

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


class SpecError(Exception):
    pass


def parse_openapi(raw: str) -> Dict[str, Any]:
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        if raw.startswith("{"):
            return json.loads(raw)
        return yaml.safe_load(raw) or {}
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SpecError(f"OpenAPI specification could not be parsed: {exc}") from exc


def spec_operations(spec: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Flatten a spec into ``{"GET /users/{id}": operation}``."""
    out: Dict[str, Dict[str, Any]] = {}
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return out
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            out[f"{method.upper()} {path}"] = operation
    return out


def _summarise(operation: Dict[str, Any]) -> Optional[str]:
    bits = [operation.get("summary"), operation.get("description")]
    security = operation.get("security")
    if security is not None:
        bits.append(f"declared security: {json.dumps(security)[:200]}")
    text = " | ".join(str(b).strip() for b in bits if b)
    return text or None


def enrich_with_openapi(
    endpoints: Sequence[ParsedEndpoint], spec: Dict[str, Any]
) -> List[ParsedEndpoint]:
    """Attach spec summaries to parsed endpoints, matching on method + path."""
    operations = spec_operations(spec)
    if not operations:
        return list(endpoints)
    for endpoint in endpoints:
        operation = operations.get(endpoint.key)
        if operation is None:
            # Tolerate parameter-name differences: /users/{id} vs /users/{user_id}
            for key, candidate in operations.items():
                if _normalise(key) == _normalise(endpoint.key):
                    operation = candidate
                    break
        if operation:
            endpoint.spec_summary = _summarise(operation)
    return list(endpoints)


def _normalise(key: str) -> str:
    out: List[str] = []
    depth = 0
    for char in key:
        if char == "{":
            depth += 1
            out.append("{")
            continue
        if char == "}":
            depth -= 1
            out.append("}")
            continue
        if depth == 0:
            out.append(char)
    return "".join(out)


def undocumented_paths(endpoints: Sequence[ParsedEndpoint], spec: Dict[str, Any]) -> List[str]:
    operations = spec_operations(spec)
    if not operations:
        return []
    documented = {_normalise(key) for key in operations}
    return [e.key for e in endpoints if _normalise(e.key) not in documented]
