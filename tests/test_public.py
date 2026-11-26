from __future__ import annotations

from openapiauth import (
    check_declared,
    check_scheme_ref,
    parse_spec,
    security_of,
    spec_batch,
)

_BEARER = {"bearerAuth": []}
_API_KEY = {"apiKeyAuth": []}

_SCHEMES = {
    "bearerAuth": {"type": "http", "scheme": "bearer"},
    "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
}

_DEFAULT = object()


def _document(paths, security=_DEFAULT):
    doc = {
        "openapi": "3.0.3",
        "paths": paths,
        "components": {"securitySchemes": dict(_SCHEMES)},
    }
    if security is _DEFAULT:
        security = [_BEARER]
    if security is not None:
        doc["security"] = security
    return doc


def test_parse_spec_indexes_paths_operations_and_security():
    post = {"operationId": "createItem", "security": [_API_KEY]}
    doc = _document(
        {
            "/items": {
                "get": {"operationId": "listItems"},
                "post": post,
            },
            "/items/{id}": {
                "delete": {"operationId": "deleteItem", "x-security-exempt": True}
            },
        }
    )

    parsed = parse_spec(doc)

    assert set(parsed["paths"]) == {"/items", "/items/{id}"}
    assert set(parsed["paths"]["/items"]["operations"]) == {"get", "post"}
    assert parsed["paths"]["/items"]["operations"]["post"] is post
    assert parsed["schemes"] == _SCHEMES
    assert security_of(parsed["paths"]["/items"]["operations"]["post"], doc) == [
        _API_KEY
    ]


def test_security_of_prefers_operation_then_path_then_global():
    path_operation = {"operationId": "report"}
    doc = _document(
        {
            "/report": {
                "security": [_API_KEY],
                "get": path_operation,
            },
            "/items": {
                "post": {"operationId": "createItem", "security": [_API_KEY]},
            },
        }
    )

    assert security_of(path_operation, doc) == [_API_KEY]
    assert security_of(doc["paths"]["/items"]["post"], doc) == [_API_KEY]


def test_check_declared_requires_security_or_explicit_exemption():
    blank = {"operationId": "blank", "security": []}
    exempt = {"operationId": "status", "x-security-exempt": True}
    missing = {"operationId": "health"}
    doc = _document(
        {
            "/blank": {"delete": blank},
            "/status": {"get": exempt},
            "/health": {"get": missing},
        },
        security=None,
    )

    assert check_declared(blank, doc) is False
    assert check_declared(exempt, doc) is True
    assert check_declared(missing, doc) is False


def test_check_scheme_ref_rejects_undefined_scheme():
    doc = _document({"/items": {"get": {"operationId": "listItems"}}})

    assert check_scheme_ref(_BEARER, doc) is True
    assert check_scheme_ref({"missingAuth": []}, doc) is False


def test_spec_batch_checks_each_document_independently():
    broken = {
        "openapi": "3.0.3",
        "paths": {
            "/purge": {
                "delete": {"operationId": "purge", "security": ["broken"]}
            }
        },
        "components": {"securitySchemes": dict(_SCHEMES)},
    }
    clean = _document(
        {
            "/items": {
                "get": {"operationId": "listItems", "security": [_BEARER]},
            }
        }
    )
    routes = {
        "purge": {"security": [_BEARER]},
        "listItems": {"security": [_BEARER]},
    }

    result = spec_batch([broken, clean], routes)

    assert result["results"][0]["allowed"] is False
    assert len(result["results"][0]["problems"]) == 1
    assert result["results"][1]["allowed"] is True
    assert result["results"][1]["problems"] == []
    assert result["allowed"] is False