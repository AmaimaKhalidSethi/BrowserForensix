import re
import html
from datetime import datetime
from typing import Any, Callable, Dict, Tuple

# --- Core validation dispatcher -------------------------------------------------

def validate_query_param(value: Any, param_type: str, **constraints) -> Any:
    """Validate and coerce a query parameter.

    Args:
        value: Raw value from request.args (usually a string).
        param_type: One of ``"string"``, ``"integer"``, ``"date"``,
            ``"regex"`` or ``"sha256"``.
        **constraints: Additional keyword arguments used by the specific
            validator (e.g. ``max_length`` for strings, ``min``/``max`` for
            integers, ``pattern`` for regexes).
    Returns:
        The coerced, safe value.
    Raises:
        ValueError: If validation fails.
    """
    param_type = param_type.lower()
    if param_type == "string":
        return _validate_string(value, **constraints)
    if param_type == "integer":
        return _validate_int(value, **constraints)
    if param_type == "date":
        return _validate_date(value, **constraints)
    if param_type == "regex":
        return _validate_regex(value, **constraints)
    if param_type == "sha256":
        return _validate_sha256(value, **constraints)
    raise ValueError(f"Unsupported param_type: {param_type}")

# --- Individual validators ------------------------------------------------------

def _validate_string(value: Any, max_length: int = 500, allow_null_bytes: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("Expected string value")
    # Strip surrounding whitespace
    cleaned = value.strip()
    if not allow_null_bytes and "\x00" in cleaned:
        raise ValueError("Null byte detected in string parameter")
    if len(cleaned) > max_length:
        raise ValueError(f"String exceeds maximum length of {max_length}")
    return cleaned

def _validate_int(value: Any, min_val: int = None, max_val: int = None) -> int:
    try:
        iv = int(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid integer value")
    if min_val is not None and iv < min_val:
        raise ValueError(f"Integer {iv} is less than minimum {min_val}")
    if max_val is not None and iv > max_val:
        raise ValueError(f"Integer {iv} exceeds maximum {max_val}")
    return iv

ISO_8601_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?)?$"
)

def _validate_date(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Date parameter must be a string")
    if not ISO_8601_REGEX.fullmatch(value.strip()):
        raise ValueError("Date is not in ISO‑8601 format")
    # ``datetime.fromisoformat`` handles most ISO‑8601 strings except the trailing 'Z'
    iso = value.rstrip('Zz')
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError as exc:
        raise ValueError("Unable to parse ISO‑8601 date") from exc
    return dt

def _validate_regex(value: Any, pattern: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Regex parameter must be a string")
    if not re.fullmatch(pattern, value):
        raise ValueError("Value does not match required pattern")
    return value

SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

def _validate_sha256(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("SHA‑256 hash must be a string")
    if not SHA256_REGEX.fullmatch(value.strip()):
        raise ValueError("Invalid SHA‑256 hash format")
    return value.strip().lower()

# --- Sanitization helpers -------------------------------------------------------

def sanitize_html(value: str) -> str:
    """Escape HTML entities to prevent XSS when echoing back user data.

    This is a thin wrapper around ``html.escape``; it can be extended later
    with a proper HTML‑sanitizer library if needed.
    """
    return html.escape(value)

# Export a convenient dict for Blueprint registration --------------------------------
VALIDATORS: Dict[str, Callable[[Any], Any]] = {
    "string": _validate_string,
    "integer": _validate_int,
    "date": _validate_date,
    "regex": _validate_regex,
    "sha256": _validate_sha256,
}
