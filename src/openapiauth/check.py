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

_GLOBAL_SECURITY_PROBLEM = "document is missing a global security declaration"
_UNDEFINED_SCHEME_PROBLEM = "security scheme is not defined"
_NO_DECLARATION_PROBLEM = "has no security declaration or explicit exemption"
_UNDEFINED_SCHEME_OP_PROBLEM = "references an undefined security scheme"
_NOT_ENFORCED_PROBLEM = "declares security that is not enforced"


def _security_schemes(doc: dict) -> dict:
    """Return the security schemes defined by a document."""
    if not isinstance(doc, dict):
        return {}
    components = doc.get("components")
    if not isinstance(components, dict):
        return {}
    schemes = components.get("securitySchemes")
    if not isinstance(schemes, dict):
        return {}
    return schemes


def _path_item_for(operation: dict, doc: dict) -> dict | None:
    """Find the path item that owns an operation object."""
    if not isinstance(doc, dict):
        return None
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return None

    # Prefer an exact identity match so duplicate-but-distinct operations are
    # resolved against the path item that actually contains them.
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

    # Fall back to structural equality for equal but detached operation copies.
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for method, candidate in path_item.items():
            if (
                isinstance(method, str)
                and method.lower() in _HTTP_METHODS
                and isinstance(candidate, dict)
                and candidate == operation
            ):
                return path_item
    return None


def _declared_requirements(doc: dict) -> Iterator[Any]:
    """Yield every requirement written at document, path, or operation scope."""
    if not isinstance(doc, dict):
        return
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
    if not isinstance(doc, dict):
        return {"security": [], "paths": {}, "schemes": {}}

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
    """Return the effective security requirements for an operation.

    The closest declaration wins: an operation-level ``security`` list takes
    precedence over a path-level list, which in turn takes precedence over the
    global ``security`` list.  As in OpenAPI, an explicit empty list at the
    closest scope overrides broader declarations; whether that empty list is a
    valid declaration is left to :func:`check_declared`.
    """
    if not isinstance(operation, dict):
        operation = {}

    operation_security = operation.get("security")
    if isinstance(operation_security, list):
        return list(operation_security)

    path_item = _path_item_for(operation, doc)
    if path_item is not None:
        path_security = path_item.get("security")
        if isinstance(path_security, list):
            return list(path_security)

    document_security = doc.get("security") if isinstance(doc, dict) else None
    if isinstance(document_security, list):
        return list(document_security)

    return []


def _is_exempt(operation: dict) -> bool:
    """Return True only for an explicit boolean ``x-security-exempt: true``."""
    return isinstance(operation, dict) and operation.get("x-security-exempt") is True


def check_declared(operation: dict, doc: dict) -> bool:
    """Report whether an operation has resolvable security or explicit exemption.

    An empty ``security`` array is neither a security declaration nor an
    exemption.  Exemption is recognized solely from a boolean-true
    ``x-security-exempt`` on the operation itself.
    """
    if _is_exempt(operation):
        return True

    return bool(security_of(operation, doc))


def check_scheme_ref(requirement: dict, doc: dict) -> bool:
    """Report whether every scheme named by a requirement is defined."""
    if not isinstance(requirement, dict) or not requirement:
        return False

    schemes = _security_schemes(doc)
    return all(isinstance(name, str) and name in schemes for name in requirement)


def _requirement_alternatives(value: Any) -> list[frozenset[str]]:
    """Normalize a security requirement value into OR-ed sets of scheme names."""
    if value is None:
        return []

    if isinstance(value, (dict, str)):
        items = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
    else:
        return []

    alternatives: list[frozenset[str]] = []
    for item in items:
        if isinstance(item, dict):
            names = frozenset(name for name in item if isinstance(name, str))
        elif isinstance(item, str) and item:
            names = frozenset({item})
        else:
            continue
        alternatives.append(names)
    return alternatives


def _enforces(actual: Any, expected: list) -> bool:
    """Return whether the route's enforced security covers the declared one."""
    expected_alternatives = _requirement_alternatives(expected)
    if not expected_alternatives:
        # Nothing declared: there is no requirement for the route to enforce.
        return True

    actual_alternatives = _requirement_alternatives(actual)
    if not actual_alternatives:
        return False

    # Every requirement object is an AND of schemes; the outer list is OR.
    # The route enforces the declaration when one of its enforcement
    # alternatives contains every scheme of one declared alternative.
    for required in expected_alternatives:
        if not required:
            continue
        for enforced in actual_alternatives:
            if required <= enforced:
                return True
    return False


def check_implemented(operation: dict, routes: dict) -> bool:
    """Report whether the registered route enforces the declared security."""
    if not isinstance(operation, dict):
        return True

    operation_id = operation.get("operationId")
    route = routes.get(operation_id) if operation_id and isinstance(routes, dict) else None

    expected = operation.get("x-effective-security")
    if expected is None:
        expected = operation.get("security", [])

    if not expected:
        return True

    if isinstance(route, dict):
        actual = route.get("security", [])
    else:
        # Tolerate registries that map an operation id directly to its
        # enforced security value (list/requirement object).
        actual = route

    return _enforces(actual, expected)


def collect_problems(doc: dict, routes: dict | None = None) -> list[str]:
    """Return every security problem found in the document's operations."""
    if routes is None:
        routes = {}

    problems: list[str] = []
    parsed = parse_spec(doc)

    for path, path_entry in parsed["paths"].items():
        for method, operation in path_entry["operations"].items():
            label = f"{method.upper()} {path}"
            effective = security_of(operation, doc)

            if not effective:
                if not check_declared(operation, doc):
                    problems.append(f"{label} {_NO_DECLARATION_PROBLEM}")
                continue

            invalid_requirement = False
            for requirement in effective:
                if not check_scheme_ref(requirement, doc):
                    problems.append(f"{label} {_UNDEFINED_SCHEME_OP_PROBLEM}")
                    invalid_requirement = True
            if invalid_requirement:
                continue

            implemented_operation = dict(operation)
            implemented_operation["x-effective-security"] = effective
            if not check_implemented(implemented_operation, routes):
                problems.append(f"{label} {_NOT_ENFORCED_PROBLEM}")

    return problems


def validate_doc(doc: dict) -> list[str]:
    """Return problems with the document's own global and scheme declarations."""
    problems: list[str] = []

    global_security = doc.get("security") if isinstance(doc, dict) else None
    if not isinstance(global_security, list) or not global_security:
        problems.append(_GLOBAL_SECURITY_PROBLEM)

    for requirement in _declared_requirements(doc):
        if not check_scheme_ref(requirement, doc):
            problems.append(_UNDEFINED_SCHEME_PROBLEM)

    return problems


def spec_batch(docs: list[dict], routes: dict | None = None) -> dict:
    """Check several documents and report each document's result separately."""
    if routes is None:
        routes = {}

    results: list[dict] = []

    for doc in docs:
        # Recomputed from scratch for every document so conclusions from one
        # document can never leak into the next.
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
