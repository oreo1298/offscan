"""JSON-lines protocol between the unprivileged client and the root helper.

Every message is one JSON object on one line, encoded as ASCII (non-ASCII
and undecodable filename bytes are carried as ``\\uXXXX`` escapes; paths
use Python's surrogateescape convention so arbitrary bytes round-trip).

Message shapes::

    {"type": "hello", "protocol": 1, "version": "...", "pid": 123}
    {"type": "req", "id": 7, "method": "drives.list", "params": {...}}
    {"type": "res", "id": 7, "ok": true, "result": ...}
    {"type": "res", "id": 7, "ok": false,
     "error": {"code": "invalid_params", "message": "..."}}
    {"type": "evt", "event": "scan.progress", "job": 3, "data": {...}}

Both sides treat the peer as untrusted: lines are size-limited, decoded
strictly, and request parameters are validated against a declared schema
before any handler sees them.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = 1
MAX_LINE = 8 * 1024 * 1024

MESSAGE_TYPES = ("hello", "req", "res", "evt")

# Error codes.  Keep this list in sync with docs/protocol.md.
INVALID_REQUEST = "invalid_request"
UNKNOWN_METHOD = "unknown_method"
INVALID_PARAMS = "invalid_params"
NOT_PERMITTED = "not_permitted"
NOT_FOUND = "not_found"
BUSY = "busy"
FAILED = "failed"
CANCELLED = "cancelled"
INTERNAL = "internal"
ERROR_CODES = (
    INVALID_REQUEST, UNKNOWN_METHOD, INVALID_PARAMS, NOT_PERMITTED,
    NOT_FOUND, BUSY, FAILED, CANCELLED, INTERNAL,
)


class ProtocolError(Exception):
    """The peer sent something that violates the protocol."""


class RemoteError(Exception):
    """A request failed on the other side."""

    def __init__(self, code: str, message: str, details: Any = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details


def _reject_constant(name: str) -> Any:
    raise ProtocolError(f"non-finite number {name} not allowed")


def encode(msg: dict[str, Any]) -> bytes:
    """Serialise one message to a newline-terminated ASCII line."""
    data = json.dumps(msg, ensure_ascii=True, separators=(",", ":"),
                      allow_nan=False)
    if len(data) >= MAX_LINE:
        raise ProtocolError("message too large")
    return data.encode("ascii") + b"\n"


def decode_line(line: bytes) -> dict[str, Any]:
    """Parse and structurally validate one line (without the newline)."""
    if len(line) > MAX_LINE:
        raise ProtocolError("line too long")
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("non-ASCII bytes on the wire") from exc
    try:
        msg = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from exc
    if not isinstance(msg, dict):
        raise ProtocolError("message is not an object")
    mtype = msg.get("type")
    if mtype not in MESSAGE_TYPES:
        raise ProtocolError(f"unknown message type {mtype!r}")
    _check_shape(mtype, msg)
    return msg


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_shape(mtype: str, msg: dict[str, Any]) -> None:
    if mtype == "hello":
        if not _is_int(msg.get("protocol")):
            raise ProtocolError("hello without protocol version")
    elif mtype == "req":
        if not _is_int(msg.get("id")) or msg["id"] < 0:
            raise ProtocolError("request id must be a non-negative integer")
        if not isinstance(msg.get("method"), str) or not msg["method"]:
            raise ProtocolError("request without method")
        if not isinstance(msg.get("params", {}), dict):
            raise ProtocolError("params must be an object")
    elif mtype == "res":
        if not _is_int(msg.get("id")):
            raise ProtocolError("response without id")
        if not isinstance(msg.get("ok"), bool):
            raise ProtocolError("response without ok flag")
        if not msg["ok"]:
            err = msg.get("error")
            if (not isinstance(err, dict) or not isinstance(err.get("code"), str)
                    or not isinstance(err.get("message"), str)):
                raise ProtocolError("malformed error object")
    elif mtype == "evt":
        if not isinstance(msg.get("event"), str) or not msg["event"]:
            raise ProtocolError("event without name")
        job = msg.get("job")
        if job is not None and not _is_int(job):
            raise ProtocolError("event job must be an integer")


class LineBuffer:
    """Incremental splitter for a byte stream of JSON lines."""

    def __init__(self, max_line: int = MAX_LINE):
        self._buf = bytearray()
        self._max = max_line

    def feed(self, data: bytes) -> list[dict[str, Any]]:
        self._buf += data
        out: list[dict[str, Any]] = []
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                if len(self._buf) > self._max:
                    raise ProtocolError("line too long")
                return out
            line = bytes(self._buf[:nl])
            del self._buf[: nl + 1]
            if line.strip():
                out.append(decode_line(line))

    @property
    def pending(self) -> int:
        return len(self._buf)


# --- message constructors --------------------------------------------------

def hello(version: str, pid: int, **extra: Any) -> dict[str, Any]:
    return {"type": "hello", "protocol": PROTOCOL_VERSION, "version": version,
            "pid": pid, **extra}


def request(req_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"type": "req", "id": req_id, "method": method, "params": params or {}}


def response_ok(req_id: int, result: Any = None) -> dict[str, Any]:
    return {"type": "res", "id": req_id, "ok": True, "result": result}


def response_error(req_id: int, code: str, message: str, details: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        err["details"] = details
    return {"type": "res", "id": req_id, "ok": False, "error": err}


def event(name: str, data: Any = None, job: int | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"type": "evt", "event": name, "data": data}
    if job is not None:
        msg["job"] = job
    return msg


# --- parameter validation --------------------------------------------------

_MISSING = object()


@dataclass(frozen=True)
class Param:
    """Declarative description of one request parameter."""

    kind: type | tuple[type, ...]
    required: bool = True
    default: Any = None
    choices: tuple[Any, ...] | None = None
    check: Callable[[Any], bool] | None = None
    items: type | None = None          # element type for lists
    max_len: int | None = None         # for str and list


@dataclass
class Schema:
    params: dict[str, Param] = field(default_factory=dict)

    def validate(self, raw: dict[str, Any]) -> dict[str, Any]:
        unknown = set(raw) - set(self.params)
        if unknown:
            raise RemoteError(INVALID_PARAMS, f"unknown parameter(s): {', '.join(sorted(unknown))}")
        clean: dict[str, Any] = {}
        for name, spec in self.params.items():
            value = raw.get(name, _MISSING)
            if value is _MISSING or value is None:
                if spec.required:
                    raise RemoteError(INVALID_PARAMS, f"missing parameter {name!r}")
                clean[name] = spec.default
                continue
            clean[name] = _check_value(name, value, spec)
        return clean


def _type_ok(value: Any, kind: type | tuple[type, ...]) -> bool:
    kinds = kind if isinstance(kind, tuple) else (kind,)
    if isinstance(value, bool):
        return bool in kinds
    if isinstance(value, int) and float in kinds and int not in kinds:
        return True
    return isinstance(value, kinds)


def _check_value(name: str, value: Any, spec: Param) -> Any:
    if not _type_ok(value, spec.kind):
        raise RemoteError(INVALID_PARAMS, f"parameter {name!r} has the wrong type")
    if isinstance(value, float) and not math.isfinite(value):
        raise RemoteError(INVALID_PARAMS, f"parameter {name!r} is not finite")
    if spec.max_len is not None and isinstance(value, (str, list)) and len(value) > spec.max_len:
        raise RemoteError(INVALID_PARAMS, f"parameter {name!r} is too long")
    if spec.items is not None and isinstance(value, list):
        for item in value:
            if not _type_ok(item, spec.items):
                raise RemoteError(INVALID_PARAMS, f"parameter {name!r} has an element of the wrong type")
    if spec.choices is not None and value not in spec.choices:
        raise RemoteError(INVALID_PARAMS, f"parameter {name!r} must be one of {list(spec.choices)}")
    if spec.check is not None and not spec.check(value):
        raise RemoteError(INVALID_PARAMS, f"parameter {name!r} is invalid")
    return value
