"""FastAPI source parser.

Endpoints are extracted with Python's own ``ast`` module rather than regular
expressions. Regex-based route extraction breaks on decorators split across
lines, nested routers, and comments containing route-like strings; an AST walk
sees the real structure and also gives exact line spans, which the dashboard
needs to link a finding back to code.

Uploaded source is *parsed*, never imported or executed.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
_PATH_PARAM = re.compile(r"\{([^}:]+)")

AUTH_HINTS = (
    "depends",
    "security",
    "oauth2",
    "httpbearer",
    "apikey",
    "current_user",
    "get_current",
    "require_",
    "authenticated",
    "token",
    "jwt",
)


@dataclass
class ParsedEndpoint:
    method: str
    path: str
    handler_name: str
    source_file: str
    source_code: str
    line_start: int
    line_end: int
    auth_dependencies: List[str] = field(default_factory=list)
    path_params: List[str] = field(default_factory=list)
    response_model: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    spec_summary: Optional[str] = None

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"


class ParseError(Exception):
    """Raised when a file cannot be parsed as Python."""


def _literal(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    return ""


def _router_prefixes(tree: ast.AST) -> Dict[str, str]:
    """Map router variable names to their ``prefix=`` value.

    ``APIRouter(prefix="/admin")`` means every decorated path in that router is
    actually mounted one level deeper. Missing this makes every reported path
    wrong, so it is resolved up front.
    """
    prefixes: Dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        callee = _dotted(node.value.func).split(".")[-1]
        if callee not in {"APIRouter", "FastAPI"}:
            continue
        prefix = ""
        for kw in node.value.keywords:
            if kw.arg == "prefix":
                prefix = _literal(kw.value) or ""
        for target in node.targets:
            if isinstance(target, ast.Name):
                prefixes[target.id] = prefix.rstrip("/")
    return prefixes


def _collect_auth_dependencies(func: ast.AST) -> List[str]:
    found: List[str] = []
    for arg_node in ast.walk(func):
        if not isinstance(arg_node, ast.Call):
            continue
        name = _dotted(arg_node.func)
        lowered = name.lower()
        if any(hint in lowered for hint in ("depends", "security")):
            for inner in arg_node.args:
                dep = _dotted(inner)
                if dep:
                    found.append(dep)
            if not arg_node.args:
                found.append(name)
    # Annotated[...] dependencies and plain default values.
    if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for arg in list(func.args.args) + list(func.args.kwonlyargs):
            ann = _dotted(arg.annotation) if arg.annotation is not None else ""
            if any(hint in (arg.arg + ann).lower() for hint in AUTH_HINTS):
                found.append(arg.arg)
    deduped: List[str] = []
    for item in found:
        if item and item not in deduped:
            deduped.append(item)
    return deduped


def parse_file(filename: str, content: str) -> List[ParsedEndpoint]:
    try:
        tree = ast.parse(content)
    except SyntaxError as exc:  # surfaced to the user, never swallowed
        raise ParseError(f"{filename}: {exc.msg} (line {exc.lineno})") from exc

    lines = content.splitlines()
    prefixes = _router_prefixes(tree)
    endpoints: List[ParsedEndpoint] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorator_names = [_dotted(d) for d in node.decorator_list]
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            dotted = _dotted(decorator.func)
            parts = dotted.split(".")
            if len(parts) < 2 or parts[-1].lower() not in HTTP_METHODS:
                continue
            method = parts[-1].upper()
            router_var = parts[-2]
            raw_path = _literal(decorator.args[0]) if decorator.args else None
            if raw_path is None:
                continue
            prefix = prefixes.get(router_var, "")
            path = (prefix + raw_path) or "/"
            if not path.startswith("/"):
                path = "/" + path

            response_model = None
            for kw in decorator.keywords:
                if kw.arg == "response_model":
                    response_model = _dotted(kw.value) or None

            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            snippet = "\n".join(lines[start - 1 : end])

            endpoints.append(
                ParsedEndpoint(
                    method=method,
                    path=path,
                    handler_name=node.name,
                    source_file=filename,
                    source_code=snippet,
                    line_start=start,
                    line_end=end,
                    auth_dependencies=_collect_auth_dependencies(node),
                    path_params=_PATH_PARAM.findall(path),
                    response_model=response_model,
                    decorators=decorator_names,
                )
            )
    return endpoints


def parse_source_files(files: Sequence[tuple[str, str]]) -> tuple[List[ParsedEndpoint], List[str]]:
    """Parse many files, returning endpoints plus non-fatal parse warnings."""
    endpoints: List[ParsedEndpoint] = []
    warnings: List[str] = []
    for filename, content in files:
        if not filename.endswith(".py"):
            continue
        try:
            endpoints.extend(parse_file(filename, content))
        except ParseError as exc:
            warnings.append(str(exc))
    endpoints.sort(key=lambda e: (e.source_file, e.line_start))
    return endpoints, warnings
