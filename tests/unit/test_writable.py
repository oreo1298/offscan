"""Writable sessions: order of protection changes, and write-protect detection."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from offscan.helper import writable
from offscan.helper.state import Layer, State


class FakeManager:
    def __init__(self, layers: list[Layer]):
        self.state = State(layers=layers)
        self.added: list[Layer] = []
        disk = SimpleNamespace(kname="sdx", path="/dev/sdx", type="disk", pkname=None, children=[])
        p1 = SimpleNamespace(kname="sdx1", path="/dev/sdx1", type="part", pkname="sdx")
        p2 = SimpleNamespace(kname="sdx2", path="/dev/sdx2", type="part", pkname="sdx")
        disk.children = [p1, p2]
        self.snap = SimpleNamespace(devices={"sdx": disk, "sdx1": p1, "sdx2": p2})

    def resolve(self, kname: str):
        return self.snap.devices[kname], self.snap

    def _root_owner(self, owner: str) -> str:
        return owner

    def _add(self, layer: Layer) -> None:
        self.added.append(layer)
        self.state.layers.append(layer)


def test_other_partitions_protected_before_disk_flag_lifted(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(writable.blockdev, "set_ro", lambda path, ro=True: calls.append((path, ro)))
    # sdx2 is mounted by us and relies on the disk-wide flag; sdx1 gets the writable session.
    mgr = FakeManager([Layer("setro", "/dev/sdx", "sdx2", {"was_ro": False})])
    writable._lift_disk_protection(mgr, "sdx1", "rw:sdx1")
    assert calls == [("/dev/sdx2", True), ("/dev/sdx", False)]
    added = [(layer.kind, layer.target) for layer in mgr.added]
    assert added == [("setro", "/dev/sdx2"), ("unsetro", "/dev/sdx")]
    assert all(layer.owner == "rw:sdx1" for layer in mgr.added)


def test_nothing_to_lift_without_a_shared_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(writable.blockdev, "set_ro", lambda path, ro=True: calls.append((path, ro)))
    mgr = FakeManager([])
    writable._lift_disk_protection(mgr, "sdx1", "rw:sdx1")
    assert calls == [] and mgr.added == []


@pytest.mark.parametrize(("layers", "current", "expected"), [
    # We set the disk flag; the partition then reports read-only but was not.
    ([Layer("setro", "/dev/sdx", "a", {"was_ro": False})], {"/dev/sdx": True, "/dev/sdx1": True}, False),
    ([Layer("setro", "/dev/sdx", "a", {"was_ro": True})], {"/dev/sdx": True, "/dev/sdx1": True}, True),
    ([Layer("setro", "/dev/sdx1", "a", {"was_ro": True})], {"/dev/sdx": False, "/dev/sdx1": True}, True),
    ([], {"/dev/sdx": False, "/dev/sdx1": True}, True),          # a write-protected partition, untouched
    ([], {"/dev/sdx": True, "/dev/sdx1": True}, True),           # e.g. an SD card's lock switch
    ([], {"/dev/sdx": False, "/dev/sdx1": False}, False),
])
def test_write_protected(monkeypatch: pytest.MonkeyPatch, layers, current, expected) -> None:
    monkeypatch.setattr(writable.blockdev, "get_ro", lambda path: current[path])
    mgr = FakeManager(layers)
    assert writable._write_protected(mgr, "/dev/sdx1", "/dev/sdx") is expected
