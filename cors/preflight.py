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

from urllib.parse import urlsplit


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

    raise NotImplementedError


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

    raise NotImplementedError


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

    raise NotImplementedError


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

    raise NotImplementedError


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

    raise NotImplementedError


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

    raise NotImplementedError


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

    raise NotImplementedError


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

    raise NotImplementedError
