"""Acceptance tests for the CORS policy helpers.

The suite is deliberately offline and deterministic: no network, no clock,
no randomness.  The same policy object is never mutated by the implementation.
"""

import pytest

from cors.preflight import (
    allow_header,
    allow_method,
    cors_batch,
    normalize_origin,
    origin_allowed,
    respond_actual,
    respond_preflight,
    validate_policy,
)

APP = "https://app.example.com"
EVIL = "https://evil.example"


def _policy(**overrides):
    policy = {
        "allow_origins": [APP],
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["content-type", "x-custom"],
        "allow_credentials": False,
        "reflect_origin": False,
    }
    policy.update(overrides)
    return policy


def test_normalize_origin_strips_default_ports_and_lowercases():
    # Defect 1: default ports must normalize, in normalization and in matching.
    assert normalize_origin("HTTPS://APP.EXAMPLE.COM:443") == APP
    assert normalize_origin("http://APP.EXAMPLE.COM:80") == "http://app.example.com"
    assert normalize_origin("https://app.example.com:8443") == "https://app.example.com:8443"
    assert origin_allowed("https://app.example.com:443", [APP]) is True
    assert origin_allowed("http://app.example.com:80", ["http://app.example.com"]) is True
    with pytest.raises(ValueError):
        normalize_origin("null")


def test_origin_allowed_rejects_suffix_confusion():
    # Defect 2: endswith/prefix host checks let a lookalike domain through.
    assert origin_allowed("https://evil-a.com", ["https://a.com"]) is False
    assert origin_allowed("https://a.com.evil.test", ["https://a.com"]) is False
    assert origin_allowed("https://evil-example.com", ["https://*.example.com"]) is False
    assert origin_allowed("https://example.com.evil.test", ["https://*.example.com"]) is False
    assert origin_allowed("https://example.com", ["https://*.example.com"]) is False
    assert origin_allowed("https://deep.api.example.com", ["https://*.example.com"]) is False
    assert origin_allowed("https://api.example.com", ["https://*.example.com"]) is True


def test_origin_allowed_rejects_null_origin():
    # Defect 3: a sandboxed document's opaque null origin must never match.
    assert origin_allowed("null", ["*"]) is False
    assert origin_allowed("null", ["null"]) is False
    assert origin_allowed("NULL", ["*"]) is False


def test_allow_method_wildcard_does_not_cover_credentials():
    # Defect 4: Access-Control-Allow-Methods: * is invalid with credentials.
    assert allow_method("PATCH", {"allow_methods": ["*"], "allow_credentials": True}) is False
    assert allow_method("PATCH", {"methods": ["*"], "credentials": True}) is False
    assert allow_method("PATCH", {"allow_methods": ["*"], "allow_credentials": False}) is True
    assert allow_method("PATCH", ["*"]) is True
    assert allow_method("PATCH", ["PUT"]) is False


def test_allow_header_is_exact_case_insensitive_not_prefix():
    # Defect 5: startswith lets x-custom-evil ride on an x-custom allow entry.
    assert allow_header("X-Custom", ["x-custom"]) is True
    assert allow_header(" Content-Type ", ["content-type"]) is True
    assert allow_header("x-custom-evil", ["x-custom"]) is False
    assert allow_header("content-type-extra", ["Content-Type"]) is False
    assert allow_header("x-nope", ["x-custom"]) is False


def test_preflight_rejects_unlisted_request_header():
    # Defect 6: the requested header list must be checked, never reflected raw.
    response = respond_preflight(
        {"origin": APP, "method": "POST", "headers": ["content-type", "x-custom-evil"]},
        _policy(),
    )
    assert response["allowed"] is False
    assert response["status"] == 403
    assert "Access-Control-Allow-Origin" not in response["headers"]
    flattened = ",".join(
        "{}:{}".format(name, value) for name, value in response["headers"].items()
    ).lower()
    assert "x-custom-evil" not in flattened


def test_actual_always_varies_on_origin():
    # Defect 7: without Vary: Origin a shared cache can leak an allow decision.
    response = respond_actual({"origin": APP}, _policy())
    assert response["allowed"] is True
    vary = [item.strip().lower() for item in response["headers"].get("Vary", "").split(",")]
    assert "origin" in vary


def test_actual_never_combines_star_origin_with_credentials():
    # Defect 8: ACAO * plus ACAC true is both invalid and a credential leak.
    response = respond_actual(
        {"origin": APP},
        _policy(allow_origins=["*"], allow_credentials=True),
    )
    assert response["allowed"] is False
    assert "Access-Control-Allow-Origin" not in response["headers"]
    assert "Access-Control-Allow-Credentials" not in response["headers"]

    plain = respond_actual(
        {"origin": APP},
        _policy(allow_origins=["*"], allow_credentials=False),
    )
    assert plain["allowed"] is True
    assert plain["headers"]["Access-Control-Allow-Origin"] == "*"
    assert "Access-Control-Allow-Credentials" not in plain["headers"]


def test_validate_policy_rejects_reflected_origin():
    # Defect 9: reflecting an arbitrary Origin is not an allowlist.
    issues = validate_policy(_policy(reflect_origin=True))
    assert any(issue.startswith("reflect_origin") for issue in issues)
    assert validate_policy(_policy()) == []


def test_batch_does_not_reuse_first_origin():
    # Defect 10: a batch must not carry the first response's ACAO to request 2.
    batch = cors_batch(
        [
            {"kind": "actual", "origin": APP},
            {"kind": "actual", "origin": EVIL},
        ],
        _policy(),
    )
    assert batch["allowed"] == [True, False]
    first, second = batch["responses"]
    assert first["headers"]["Access-Control-Allow-Origin"] == APP
    assert "Access-Control-Allow-Origin" not in second["headers"]
    assert first["headers"] != second["headers"]


def test_allowlisted_origin_preflight_succeeds():
    response = respond_preflight(
        {"origin": APP, "method": "POST", "headers": ["Content-Type"]},
        _policy(),
    )
    assert response["allowed"] is True
    assert response["status"] == 204
    headers = response["headers"]
    assert headers["Access-Control-Allow-Origin"] == APP
    assert headers["Access-Control-Allow-Methods"] == "POST"
    assert headers["Access-Control-Allow-Headers"] == "content-type"
    assert "Access-Control-Allow-Credentials" not in headers
    vary = [item.strip().lower() for item in headers["Vary"].split(",")]
    assert vary == [
        "origin",
        "access-control-request-method",
        "access-control-request-headers",
    ]


def test_disallowed_origin_gets_no_allow_origin():
    response = respond_actual({"origin": EVIL}, _policy())
    assert response["allowed"] is False
    assert "Access-Control-Allow-Origin" not in response["headers"]
    assert "Access-Control-Allow-Credentials" not in response["headers"]


def test_credentialed_request_cannot_use_star():
    star_origin = _policy(allow_origins=["*"], allow_credentials=True)
    response = respond_preflight(
        {"origin": APP, "method": "GET", "headers": []},
        star_origin,
    )
    assert response["allowed"] is False
    assert response["status"] == 403
    assert "Access-Control-Allow-Origin" not in response["headers"]
    assert any(
        issue.startswith("wildcard_origin_with_credentials")
        for issue in validate_policy(star_origin)
    )

    star_method = _policy(allow_methods=["*"], allow_credentials=True)
    method_response = respond_preflight(
        {"origin": APP, "method": "GET", "headers": []},
        star_method,
    )
    assert method_response["allowed"] is False
    assert method_response["status"] == 403
    assert any(
        issue.startswith("wildcard_method_with_credentials")
        for issue in validate_policy(star_method)
    )


def test_preflight_denial_uses_403_semantics():
    response = respond_preflight(
        {"origin": EVIL, "method": "GET", "headers": []},
        _policy(),
    )
    assert response["allowed"] is False
    assert response["status"] == 403
    assert response["headers"] == {}


def test_batch_matches_individual_decisions():
    policy = _policy()
    requests = [
        {"kind": "actual", "origin": APP},
        {"kind": "actual", "origin": EVIL},
    ]
    expected = [respond_actual(request, policy) for request in requests]
    batch = cors_batch(requests, policy)
    assert batch["responses"] == expected
    assert batch["allowed"] == [item["allowed"] for item in expected]
    assert batch["responses"][0] is not batch["responses"][1]
