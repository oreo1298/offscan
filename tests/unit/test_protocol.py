import json
import os

import pytest

from offscan import protocol as p
from offscan.names import display, from_wire, to_wire


def test_roundtrip_request() -> None:
    msg = p.request(3, "drives.list", {"all": True})
    line = p.encode(msg)
    assert line.endswith(b"\n") and line.count(b"\n") == 1
    assert p.decode_line(line[:-1]) == msg


def test_hostile_path_roundtrips_and_is_ascii_on_the_wire() -> None:
    raw = b"evil\nname\xff\xfe\x1b[31m\xe2\x80\xae.exe"
    msg = p.event("scan.detection", {"path": to_wire(raw)}, job=1)
    line = p.encode(msg)
    line.decode("ascii")  # must not raise
    assert b"\n" not in line[:-1]
    back = p.decode_line(line[:-1])
    assert from_wire(back["data"]["path"]) == raw


def test_display_escapes_control_and_bidi() -> None:
    raw = b"a\nb\xff\x1b[0m\xe2\x80\xaeexe.txt"
    shown = display(raw)
    assert "\n" not in shown and "\x1b" not in shown and "‮" not in shown
    assert "\\n" in shown and "\\xff" in shown and "\\u202e" in shown
    assert display("x" * 50, max_len=11).count("…") == 1


@pytest.mark.parametrize("line", [
    b"", b"[]", b"42", b'{"type":"nope"}', b'{"type":"req","id":-1,"method":"x"}',
    b'{"type":"req","id":true,"method":"x"}', b'{"type":"req","id":1,"method":""}',
    b'{"type":"req","id":1,"method":"x","params":[]}', b'{"type":"res","id":1}',
    b'{"type":"res","id":1,"ok":false,"error":"x"}', b'{"type":"evt"}',
    b'{"type":"evt","event":"x","job":"1"}', b'{"type":"hello"}',
    b'{"type":"req","id":1,"method":"x","params":{"a":NaN}}',
    b'{"type":"req","id":1,"method":"x","params":{"a":Infinity}}',
    "{\"type\":\"evt\",\"event\":\"é\"}".encode(),
    b"{" * 100000,
])
def test_rejects_malformed(line: bytes) -> None:
    with pytest.raises(p.ProtocolError):
        p.decode_line(line)


def test_encode_rejects_nan() -> None:
    with pytest.raises(ValueError):
        p.encode({"type": "evt", "event": "x", "data": float("nan")})


def test_line_buffer_splits_and_limits() -> None:
    buf = p.LineBuffer(max_line=64)
    data = p.encode(p.response_ok(1, 5)) + p.encode(p.event("e"))
    out = buf.feed(data[:7]) + buf.feed(data[7:])
    assert [m["type"] for m in out] == ["res", "evt"]
    assert buf.pending == 0
    with pytest.raises(p.ProtocolError):
        buf.feed(b"x" * 65)


def test_schema_validation() -> None:
    schema = p.Schema({
        "device": p.Param(str, max_len=10),
        "readonly": p.Param(bool, required=False, default=True),
        "depth": p.Param(int, required=False, default=3, check=lambda v: 0 <= v <= 20),
        "mode": p.Param(str, required=False, default="quick", choices=("quick", "full")),
        "paths": p.Param(list, required=False, default=[], items=str),
        "ratio": p.Param(float, required=False, default=1.0),
    })
    assert schema.validate({"device": "sda1"}) == {
        "device": "sda1", "readonly": True, "depth": 3, "mode": "quick", "paths": [], "ratio": 1.0}
    assert schema.validate({"device": "x", "ratio": 2})["ratio"] == 2
    bad = [
        {}, {"device": 5}, {"device": "x", "readonly": 1}, {"device": "x", "depth": True},
        {"device": "x", "depth": 99}, {"device": "x", "mode": "slow"}, {"device": "x" * 11},
        {"device": "x", "paths": ["a", 1]}, {"device": "x", "extra": 1},
        {"device": "x", "ratio": float("inf")},
    ]
    for params in bad:
        with pytest.raises(p.RemoteError) as info:
            schema.validate(params)
        assert info.value.code == p.INVALID_PARAMS


def test_error_response_shape() -> None:
    msg = p.response_error(9, p.NOT_PERMITTED, "no", {"why": "x"})
    assert p.decode_line(p.encode(msg)[:-1])["error"]["details"] == {"why": "x"}
    assert set(p.ERROR_CODES) >= {p.NOT_PERMITTED, p.INTERNAL}


def test_wire_format_is_compact_json() -> None:
    line = p.encode(p.hello("1.0", os.getpid()))
    assert json.loads(line)["protocol"] == p.PROTOCOL_VERSION
    assert b" " not in line
