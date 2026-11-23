"""CORS policy helpers for a first-party API.

A policy is a mapping with this shape::

    {
        "allow_origins": ["https://app.example.com", "https://*.example.net"],
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["content-type", "x-custom"],
        "allow_credentials": False,
        "reflect_origin": False,
    }

An ordinary request is a mapping containing ``origin``.  A preflight request
also contains ``method`` (the Access-Control-Request-Method) and may contain
``headers`` (the Access-Control-Request-Headers).  Response functions return::

    {"allowed": bool, "status": int, "headers": {"Header-Name": "value"}}

Origin handling has zero tolerance: after normalization the scheme, host and
port must all match.  There is no suffix, prefix, implicit-port, ``null`` or
case-insensitive-host fallback.  Credentialed CORS never uses the ``*``
wildcard for origins or methods.
"""

import re
from collections.abc import Mapping
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}

# RFC 7230 ``tchar``; anything outside this set is a malformed token.
_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~"
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

_MISSING = object()


def _is_token(value) -> bool:
    """Return whether ``value`` is a non-empty RFC 7230 token."""
    return (
        isinstance(value, str)
        and bool(value)
        and all(char in _TOKEN_CHARS for char in value)
    )


def _split_host_port(netloc):
    """Split ``netloc`` into ``(host, port, is_ipv6)``.

    Raises ``ValueError`` for userinfo, an empty host, unbracketed IPv6, or an
    empty/non-numeric/out-of-range port.
    """
    if "@" in netloc:
        raise ValueError("userinfo is not allowed in an origin")
    if not netloc:
        raise ValueError("origin has no host")

    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            raise ValueError("unterminated IPv6 literal")
        host = netloc[1:end]
        rest = netloc[end + 1:]
        if rest:
            if not rest.startswith(":"):
                raise ValueError("unexpected text after IPv6 literal")
            port_text = rest[1:]
        else:
            port_text = None
        if not host or ":" not in host:
            raise ValueError("invalid IPv6 literal")
        is_ipv6 = True
    else:
        if netloc.count(":") > 1:
            raise ValueError("IPv6 literals must be bracketed")
        if ":" in netloc:
            host, _, port_text = netloc.partition(":")
        else:
            host, port_text = netloc, None
        if not host:
            raise ValueError("origin has no host")
        is_ipv6 = False

    if port_text is None:
        port = None
    else:
        # An empty or non-ASCII-numeric port is invalid; ``isdigit`` would
        # accept non-ASCII digits, so match explicitly.
        if re.fullmatch(r"[0-9]+", port_text) is None:
            raise ValueError("origin port is not numeric")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError("origin port is out of range")

    return host.lower(), port, is_ipv6


def _as_list(value):
    """Return a list for a sequence of policy entries, else ``None``."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return None


def _policy_get(policy, primary, alias=None, default=None):
    """Read ``primary`` (or its ``alias``) from a policy mapping."""
    if isinstance(policy, Mapping):
        if primary in policy:
            return policy[primary]
        if alias is not None and alias in policy:
            return policy[alias]
    return default


def _parse_subdomain_pattern(entry):
    """Parse ``scheme://*.example.com[:port]`` into ``(scheme, base, port)``.

    Returns ``None`` when ``entry`` is not a valid explicit subdomain pattern.
    """
    if not isinstance(entry, str) or not entry:
        return None
    if any(char.isspace() for char in entry) or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in entry
    ):
        return None
    if "://" not in entry:
        return None

    scheme, _, rest = entry.partition("://")
    scheme = scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    if not rest or any(char in rest for char in "/?#"):
        return None

    try:
        host, port, is_ipv6 = _split_host_port(rest)
    except ValueError:
        return None

    if is_ipv6 or ":" in host:
        return None
    if not host.startswith("*."):
        return None

    base = host[2:]
    if not base or "*" in base:
        return None

    if port == _DEFAULT_PORTS[scheme]:
        port = None
    return scheme, base, port


def _valid_origin_entry(entry) -> bool:
    """Return whether an allowlist entry is a valid exact/wildcard origin."""
    if "*" in entry:
        return _parse_subdomain_pattern(entry) is not None
    try:
        normalize_origin(entry)
    except (TypeError, ValueError):
        return False
    return True


def normalize_origin(origin: str) -> str:
    """Normalize an Origin value to its serialized origin form.

    Contract:
    * The input must be an absolute ``http`` or ``https`` origin of the form
      ``scheme://host[:port]``.  Userinfo, a path (including a trailing
      slash), query, fragment, whitespace, and opaque values such as
      ``"null"`` are invalid and raise ``ValueError``.
    * Scheme and host are lower-cased.
    * The default port is removed: 80 for http and 443 for https.  A
      non-default port is preserved exactly.  A port must be an integer in
      1..65535; an empty or non-numeric port is invalid.
    * An IPv6 host is returned inside brackets.
    * Tolerance is zero: the function never guesses a scheme, adds a port,
      strips a suffix, performs IDNA conversion, or treats ``null`` as an
      origin.
    * The result is ``scheme://host`` or ``scheme://host:port``.
    """

    if not isinstance(origin, str) or not origin:
        raise ValueError("origin must be a non-empty string")
    if any(char.isspace() for char in origin) or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in origin
    ):
        raise ValueError("origin contains whitespace or control characters")

    try:
        parts = urlsplit(origin)
    except ValueError as exc:
        raise ValueError("invalid origin") from exc

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError("origin scheme must be http or https")
    if not parts.netloc:
        raise ValueError("origin must be absolute")
    if parts.path or parts.query or parts.fragment:
        raise ValueError("origin must not contain a path, query, or fragment")
    # ``urlsplit`` cannot distinguish a trailing '?'/'#' from an absent one,
    # and both are forbidden in a serialized origin.
    if "?" in origin or "#" in origin:
        raise ValueError("origin must not contain a query or fragment")

    host, port, is_ipv6 = _split_host_port(parts.netloc)
    if port == _DEFAULT_PORTS[scheme]:
        port = None

    host_text = "[{}]".format(host) if is_ipv6 else host
    if port is None:
        return "{}://{}".format(scheme, host_text)
    return "{}://{}:{}".format(scheme, host_text, port)


def origin_allowed(origin: str, allow) -> bool:
    """Return whether ``origin`` matches an explicit allowlist entry.

    ``allow`` is a sequence whose entries are one of:

    * an exact origin such as ``https://app.example.com``;
    * the literal ``"*"``, which matches every valid non-null origin;
    * an explicit subdomain pattern such as ``https://*.example.com``.

    Contract:
    * ``origin`` is normalized first.  Invalid values, including ``"null"``
      and ``"*"``, return ``False``; this function never raises for
      attacker-controlled input.
    * ``null`` is never a valid allowlist entry and can never match.
    * A wildcard is valid only as the entire left-most host label.  It
      matches exactly one additional label and never the apex domain, so
      ``https://*.example.com`` matches ``https://api.example.com`` but not
      ``https://example.com``, ``https://a.b.example.com``, or
      ``https://example.com.evil.test``.
    * Scheme, host, and port must match after normalization.  No suffix,
      prefix, or substring matching is allowed: ``https://evil-a.com`` does
      not match ``https://a.com`` and ``https://a.com.evil.test`` does not
      match ``https://a.com``.
    """

    try:
        normalized = normalize_origin(origin)
    except (TypeError, ValueError):
        return False

    entries = _as_list(allow)
    if entries is None:
        return False

    parsed = urlsplit(normalized)
    norm_scheme = parsed.scheme.lower()
    norm_host = (parsed.hostname or "").lower()
    norm_port = parsed.port

    for entry in entries:
        if not isinstance(entry, str):
            continue
        if entry == "*":
            return True
        if entry.lower() == "null":
            continue

        pattern = _parse_subdomain_pattern(entry)
        if pattern is not None:
            pattern_scheme, base, pattern_port = pattern
            if pattern_scheme != norm_scheme or pattern_port != norm_port:
                continue
            suffix = "." + base
            if not norm_host.endswith(suffix):
                continue
            label = norm_host[: -len(suffix)]
            # Exactly one additional, non-empty label: no apex, no nesting.
            if label and "." not in label:
                return True
            continue

        try:
            if normalize_origin(entry) == normalized:
                return True
        except (TypeError, ValueError):
            continue

    return False


def allow_method(method: str, allowed) -> bool:
    """Return whether a request method is authorized.

    ``allowed`` is either a sequence of methods or a policy-like mapping with
    ``allow_methods`` (alias ``methods``) and ``allow_credentials`` (alias
    ``credentials``).

    Contract:
    * Method tokens are compared case-sensitively, as HTTP methods are.
      Empty or malformed tokens return ``False``.
    * An exact member of the allowlist is always authorized.
    * Literal ``"*"`` in a sequence authorizes a concrete method only for a
      non-credentialed request.  When credentials are true, ``"*"`` never
      authorizes a concrete method; an explicit method is required.  This
      models the CORS rule that a wildcard methods response is invalid for
      credentialed requests.
    * A requested method of ``"*"`` is not a concrete method and returns
      ``False``.
    """

    if not _is_token(method) or method == "*":
        return False

    if isinstance(allowed, Mapping):
        methods = _policy_get(allowed, "allow_methods", "methods", [])
        credentials = bool(
            _policy_get(allowed, "allow_credentials", "credentials", False)
        )
    else:
        methods = allowed
        credentials = False

    entries = _as_list(methods)
    if entries is None:
        return False

    for entry in entries:
        if entry == method:
            return True

    if not credentials and "*" in entries:
        return True

    return False


def allow_header(header: str, allowed) -> bool:
    """Return whether a requested header is authorized.

    Contract:
    * Header names are compared case-insensitively, exactly, after trimming
      surrounding optional whitespace.
    * The match is a whole field-name match.  ``x-custom-evil`` does not match
      ``x-custom`` and ``content-type-extra`` does not match
      ``content-type``.
    * A wildcard entry is not supported by this function; a header must be
      named explicitly in ``allowed``.  Invalid tokens (empty, containing a
      colon, comma, internal whitespace, CR, or LF) return ``False``.
    """

    if not isinstance(header, str):
        return False

    name = header.strip(" \t")
    if not _is_token(name):
        return False

    if isinstance(allowed, Mapping):
        allowed = _policy_get(allowed, "allow_headers", "headers", [])
    entries = _as_list(allowed)
    if entries is None:
        return False

    lowered = name.lower()
    for entry in entries:
        if not isinstance(entry, str):
            continue
        candidate = entry.strip(" \t")
        # ``"*"`` is a wildcard entry, which this function does not support.
        if candidate == "*":
            continue
        if candidate.lower() == lowered:
            return True

    return False


def respond_preflight(req, policy) -> dict:
    """Produce the decision and CORS headers for a preflight request.

    ``req`` has ``origin``, ``method`` (Access-Control-Request-Method), and
    optionally ``headers`` (Access-Control-Request-Headers).  The origin,
    method, and every requested header must pass, and the policy must not use
    a wildcard origin or method together with credentials.

    Contract:
    * A denial returns ``{"allowed": False, "status": 403, "headers": {}}``.
      No partial ``Access-Control-Allow-*`` header is emitted on denial.
    * Success returns status 204 and fresh headers:
      ``Access-Control-Allow-Origin`` is the normalized request origin, or
      ``"*"`` only when the policy literally allows ``"*"`` and credentials
      are disabled; ``Access-Control-Allow-Methods`` is the requested method;
      ``Access-Control-Allow-Headers`` contains only the validated requested
      header names, lower-cased and joined by ``, `` (omitted when none were
      requested); ``Access-Control-Allow-Credentials`` is ``"true"`` only when
      credentials are enabled.
    * ``Vary`` is
      ``"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"``.
    * The unvalidated ``Access-Control-Request-Headers`` value is never copied
      through to the response.
    """

    deny = {"allowed": False, "status": 403, "headers": {}}

    if not isinstance(req, Mapping):
        return deny

    origin = req.get("origin")
    method = req.get("method")

    origins = _policy_get(policy, "allow_origins", default=[])
    methods = _policy_get(policy, "allow_methods", "methods", [])
    header_allow = _policy_get(policy, "allow_headers", "headers", [])
    credentials = bool(
        _policy_get(policy, "allow_credentials", "credentials", False)
    )

    origin_entries = _as_list(origins)
    method_entries = _as_list(methods)
    header_entries = _as_list(header_allow)
    if origin_entries is None or method_entries is None or header_entries is None:
        return deny

    # A wildcard response is invalid for credentialed requests; such a policy
    # is self-contradictory and must be rejected outright.
    if credentials and "*" in origin_entries:
        return deny
    if credentials and "*" in method_entries:
        return deny

    if not origin_allowed(origin, origin_entries):
        return deny
    method_target = policy if isinstance(policy, Mapping) else method_entries
    if not allow_method(method, method_target):
        return deny

    raw_headers = req.get("headers", [])
    if raw_headers is None:
        raw_headers = []
    if isinstance(raw_headers, str):
        requested = [] if not raw_headers.strip() else raw_headers.split(",")
    elif isinstance(raw_headers, (list, tuple, set, frozenset)):
        requested = list(raw_headers)
    else:
        return deny

    validated = []
    seen = set()
    for header in requested:
        if not allow_header(header, header_entries):
            return deny
        canonical = header.strip(" \t").lower()
        if canonical not in seen:
            seen.add(canonical)
            validated.append(canonical)

    if "*" in origin_entries and not credentials:
        allow_origin = "*"
    else:
        allow_origin = normalize_origin(origin)

    headers = {
        "Access-Control-Allow-Origin": allow_origin,
        "Access-Control-Allow-Methods": method,
        "Vary": (
            "Origin, Access-Control-Request-Method, "
            "Access-Control-Request-Headers"
        ),
    }
    if validated:
        headers["Access-Control-Allow-Headers"] = ", ".join(validated)
    if credentials:
        headers["Access-Control-Allow-Credentials"] = "true"

    return {"allowed": True, "status": 204, "headers": headers}


def respond_actual(req, policy) -> dict:
    """Produce the decision and CORS headers for an actual request.

    Only the request origin is gated; method and header allowlists belong to
    preflight and are not applied here.

    Contract:
    * A denial returns status 200 with ``"allowed": False`` and only
      ``Vary: Origin`` in ``headers``.  It emits no
      ``Access-Control-Allow-Origin`` or
      ``Access-Control-Allow-Credentials``.
    * A successful response always includes ``Vary: Origin`` so a shared
      cache cannot serve one origin's allow header to another origin.
    * ``Access-Control-Allow-Origin`` is ``"*"`` only when the policy
      literally allows ``"*"`` and credentials are disabled; otherwise it is
      the normalized request origin that matched the allowlist.
    * Literal ``"*"`` in ``allow_origins`` together with credentials is an
      invalid policy and is denied at runtime.
      ``Access-Control-Allow-Credentials: true`` is never combined with
      ``Access-Control-Allow-Origin: *``.
    * A policy with ``reflect_origin`` enabled is denied rather than echoing
      an arbitrary origin.
    """

    # Both success and denial vary on Origin: a shared cache must never reuse
    # one origin's allow header for another origin.
    deny = {"allowed": False, "status": 200, "headers": {"Vary": "Origin"}}

    if not isinstance(req, Mapping):
        return deny

    origin = req.get("origin")
    origins = _policy_get(policy, "allow_origins", default=[])
    credentials = bool(
        _policy_get(policy, "allow_credentials", "credentials", False)
    )
    reflect_origin = _policy_get(policy, "reflect_origin", default=False)

    entries = _as_list(origins)
    if entries is None:
        return deny

    # Reflecting an arbitrary Origin bypasses any allowlist.
    if reflect_origin:
        return deny

    # "*" plus credentials is both invalid CORS and a credential leak.
    if credentials and "*" in entries:
        return deny

    if not origin_allowed(origin, entries):
        return deny

    if "*" in entries and not credentials:
        allow_origin = "*"
    else:
        allow_origin = normalize_origin(origin)

    headers = {
        "Access-Control-Allow-Origin": allow_origin,
        "Vary": "Origin",
    }
    if credentials:
        headers["Access-Control-Allow-Credentials"] = "true"

    return {"allowed": True, "status": 200, "headers": headers}


def validate_policy(policy) -> list[str]:
    """Return a list of security problems in a CORS policy.

    An empty list means no known problem.  Malformed input produces issue
    strings instead of raising.  Each issue starts with one of these stable
    codes:

    * ``reflect_origin:`` -- the policy asks the server to echo arbitrary
      request origins instead of using an explicit allowlist;
    * ``wildcard_origin_with_credentials:`` -- ``"*"`` in ``allow_origins``
      is incompatible with ``allow_credentials``;
    * ``wildcard_method_with_credentials:`` -- ``"*"`` in ``allow_methods``
      is incompatible with ``allow_credentials``;
    * ``wildcard_header_with_credentials:`` -- ``"*"`` in ``allow_headers``
      is incompatible with ``allow_credentials``;
    * ``null_origin:`` -- ``null`` is accepted as an allowlist entry;
    * ``invalid_origin:`` -- an allowlist entry is neither an exact origin nor
      a valid explicit ``https://*.example.com`` pattern;
    * ``invalid_policy:`` -- the policy or one of its fields has the wrong
      shape.

    Checks involving ``"*"`` apply only when credentials are enabled.  A
    non-credentialed wildcard can be a deliberate choice.
    """

    if not isinstance(policy, Mapping):
        return ["invalid_policy: policy must be a mapping"]

    issues = []

    reflect_origin = policy.get("reflect_origin", False)
    if not isinstance(reflect_origin, bool):
        issues.append("invalid_policy: reflect_origin must be a boolean")
    if reflect_origin:
        issues.append(
            "reflect_origin: policy echoes arbitrary request origins instead "
            "of using an explicit allowlist"
        )

    credentials = policy.get("allow_credentials", policy.get("credentials", False))
    if not isinstance(credentials, bool):
        issues.append("invalid_policy: allow_credentials must be a boolean")

    # --- Origins ---------------------------------------------------------
    origins = policy.get("allow_origins", [])
    if not isinstance(origins, (list, tuple, set, frozenset)):
        issues.append("invalid_policy: allow_origins must be a sequence")
    else:
        wildcard_origin = False
        for entry in origins:
            if not isinstance(entry, str):
                issues.append("invalid_origin: allowlist entry is not a string")
                continue
            if entry.lower() == "null":
                issues.append("null_origin: null is not a valid origin")
                continue
            if entry == "*":
                wildcard_origin = True
                continue
            if not _valid_origin_entry(entry):
                issues.append(
                    "invalid_origin: {!r} is not a valid origin or explicit "
                    "subdomain pattern".format(entry)
                )
        if wildcard_origin and credentials:
            issues.append(
                "wildcard_origin_with_credentials: '*' cannot be combined "
                "with credentials"
            )

    # --- Methods ---------------------------------------------------------
    methods = policy.get("allow_methods", policy.get("methods", []))
    if not isinstance(methods, (list, tuple, set, frozenset)):
        issues.append("invalid_policy: allow_methods must be a sequence")
    else:
        invalid_method = False
        wildcard_method = False
        for entry in methods:
            if not _is_token(entry):
                invalid_method = True
            elif entry == "*":
                wildcard_method = True
        if invalid_method:
            issues.append("invalid_policy: allow_methods contains invalid tokens")
        if wildcard_method and credentials:
            issues.append(
                "wildcard_method_with_credentials: '*' cannot be combined "
                "with credentials"
            )

    # --- Headers ---------------------------------------------------------
    headers = policy.get("allow_headers", policy.get("headers", []))
    if not isinstance(headers, (list, tuple, set, frozenset)):
        issues.append("invalid_policy: allow_headers must be a sequence")
    else:
        invalid_header = False
        wildcard_header = False
        for entry in headers:
            name = entry.strip(" \t") if isinstance(entry, str) else entry
            if not _is_token(name):
                invalid_header = True
            elif name == "*":
                wildcard_header = True
        if invalid_header:
            issues.append("invalid_policy: allow_headers contains invalid tokens")
        if wildcard_header and credentials:
            issues.append(
                "wildcard_header_with_credentials: '*' cannot be combined "
                "with credentials"
            )

    return issues


def cors_batch(requests, policy) -> dict:
    """Evaluate independent CORS requests against one immutable policy.

    Each request is a mapping with ``kind`` set to ``"preflight"`` or
    ``"actual"`` (default ``"actual"``), plus the fields accepted by the
    corresponding ``respond_*`` function.

    Contract:
    * The return value is
      ``{"responses": [response, ...], "allowed": [bool, ...]}`` in input
      order.
    * Every response is computed independently and is a fresh mapping.  No
      response headers, including ``Access-Control-Allow-Origin``, are reused
      or carried over from an earlier request.
    * Each response must equal the result of calling ``respond_preflight`` or
      ``respond_actual`` directly for that request.
    * An unknown ``kind`` is denied with
      ``{"allowed": False, "status": 400, "headers": {}}`` instead of
      aborting the batch.
    """

    denied = {"allowed": False, "status": 400, "headers": {}}
    responses = []

    for request in requests:
        if not isinstance(request, Mapping):
            responses.append(dict(denied))
            continue

        kind = request.get("kind", "actual")
        if kind == "preflight":
            responses.append(respond_preflight(request, policy))
        elif kind == "actual":
            responses.append(respond_actual(request, policy))
        else:
            responses.append(dict(denied))

    return {
        "responses": responses,
        "allowed": [response["allowed"] for response in responses],
    }
