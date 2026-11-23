"""CORS preflight and actual-response policy helpers."""

from .preflight import (
    allow_header,
    allow_method,
    cors_batch,
    normalize_origin,
    origin_allowed,
    respond_actual,
    respond_preflight,
    validate_policy,
)

__all__ = [
    "normalize_origin",
    "origin_allowed",
    "allow_method",
    "allow_header",
    "respond_preflight",
    "respond_actual",
    "validate_policy",
    "cors_batch",
]
