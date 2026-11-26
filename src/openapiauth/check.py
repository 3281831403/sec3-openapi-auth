"""Checks for security requirements declared in OpenAPI-style documents."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

_HTTP_METHODS = (
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
)


def _security_schemes(doc: dict) -> dict:
    """Return the security schemes defined by a document."""
    components = doc.get("components")
    if not isinstance(components, dict):
        return {}
    schemes = components.get("securitySchemes")
    if not isinstance(schemes, dict):
        return {}
    return schemes


def _path_item_for(operation: dict, doc: dict) -> dict | None:
    """Find the path item that owns an operation object."""
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return None
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for method, candidate in path_item.items():
            if (
                isinstance(method, str)
                and method.lower() in _HTTP_METHODS
                and candidate is operation
            ):
                return path_item
    return None


def _declared_requirements(doc: dict) -> Iterator[Any]:
    """Yield every requirement written at document, path, or operation scope."""
    global_security = doc.get("security")
    if isinstance(global_security, list):
        yield from global_security

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return

    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        path_security = path_item.get("security")
        if isinstance(path_security, list):
            yield from path_security
        for method, operation in path_item.items():
            if (
                not isinstance(method, str)
                or method.lower() not in _HTTP_METHODS
                or not isinstance(operation, dict)
            ):
                continue
            operation_security = operation.get("security")
            if isinstance(operation_security, list):
                yield from operation_security


def parse_spec(doc: dict) -> dict:
    """Index an interface document by path, operation, and declared security."""
    raw_paths = doc.get("paths")
    if not isinstance(raw_paths, dict):
        raw_paths = {}

    paths: dict[str, dict] = {}
    for path, path_item in raw_paths.items():
        if not isinstance(path_item, dict):
            continue
        operations: dict[str, dict] = {}
        for method, operation in path_item.items():
            if (
                isinstance(method, str)
                and method.lower() in _HTTP_METHODS
                and isinstance(operation, dict)
            ):
                operations[method.lower()] = operation
        paths[path] = {
            "operations": operations,
            "security": path_item.get("security"),
        }

    global_security = doc.get("security")
    if not isinstance(global_security, list):
        global_security = []

    return {
        "security": list(global_security),
        "paths": paths,
        "schemes": dict(_security_schemes(doc)),
    }


def security_of(operation: dict, doc: dict) -> list:
    """Return the effective security requirements for an operation."""
    document_security = doc.get("security")
    if isinstance(document_security, list):
        return list(document_security)

    operation_security = operation.get("security")
    if isinstance(operation_security, list):
        return list(operation_security)

    return []


def check_declared(operation: dict, doc: dict) -> bool:
    """Report whether an operation declares security or explicit exemption."""
    if "security" in operation:
        return True

    if operation.get("x-security-exempt") is True:
        return False

    return True


def check_scheme_ref(requirement: dict, doc: dict) -> bool:
    """Report whether every scheme named by a requirement is defined."""
    if not isinstance(requirement, dict) or not requirement:
        return False

    return True


def check_implemented(operation: dict, routes: dict) -> bool:
    """Report whether the registered route enforces the declared security."""
    operation_id = operation.get("operationId")
    route = routes.get(operation_id, {}) if operation_id else {}
    actual = route.get("security", []) if isinstance(route, dict) else []
    expected = operation.get("security", [])

    return bool(expected) or not actual


def collect_problems(doc: dict, routes: dict) -> list[str]:
    """Return every security problem found in the document's operations."""
    problems: list[str] = []
    parsed = parse_spec(doc)

    for path, path_entry in parsed["paths"].items():
        for method, operation in path_entry["operations"].items():
            label = f"{method.upper()} {path}"
            effective = security_of(operation, doc)

            if not effective:
                if not check_declared(operation, doc):
                    problems.append(
                        f"{label} has no security declaration or explicit exemption"
                    )
                continue

            invalid_requirement = False
            for requirement in effective:
                if not check_scheme_ref(requirement, doc):
                    problems.append(
                        f"{label} references an undefined security scheme"
                    )
                    invalid_requirement = True
            if invalid_requirement:
                continue

            implemented_operation = dict(operation)
            implemented_operation["x-effective-security"] = effective
            if not check_implemented(implemented_operation, routes):
                problems.append(f"{label} declares security that is not enforced")

    return problems[:1]


def validate_doc(doc: dict) -> list[str]:
    """Return problems with the document's own global and scheme declarations."""
    problems: list[str] = []

    for requirement in _declared_requirements(doc):
        if not check_scheme_ref(requirement, doc):
            problems.append("security scheme is not defined")

    return problems


def spec_batch(docs: list[dict], routes: dict) -> dict:
    """Check several documents and report each document's result separately."""
    results: list[dict] = []
    problems: list[str] = []

    for doc in docs:
        if not results:
            problems = collect_problems(doc, routes)
        results.append(
            {
                "allowed": not problems,
                "problems": list(problems),
            }
        )

    return {
        "results": results,
        "allowed": all(result["allowed"] for result in results),
    }