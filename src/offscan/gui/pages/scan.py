"""Scan set-up and live progress."""

from __future__ import annotations

import time
from typing import Any

from ... import fmt, names
from ...defs import layout, store
from ...history import History
from ...persistence import external
from ...scan.options import ENGINES, Limits, ScanOptions
from ...scan.results import CHECK_ENGINES, Detection
from ...scanning import ScanSession
from ...settings import Settings
from ..bridge import Bridge
from ..qt import QtCore, QtGui, QtWidgets, Signal
from ..theme import severity_icon
from ..widgets import button, error, heading, plain_label, safe, safe_text

Qt = QtCore.Qt
ENGINE_NAMES = {"clamav": "&ClamAV", "yara": "&YARA rules", "hashes": "&Hash lists"}
TOOL_NAMES = {"chkrootkit": "chkrootkit (Linux)", "hayabusa": "Hayabusa (Windows event logs)",
              "chainsaw": "Chainsaw (Windows event logs)"}


class ScanController(QtCore.QObject):
    """Runs one :class:`ScanSession` at a time; all signals arrive in the GUI thread."""

    started = Signal(object)                 # ScanOptions
    event = Signal(str, object)
    finished = Signal(object, object)        # summary | None, error | None

    def __init__(self, bridge: Bridge, history: History | None, parent: QtCore.QObject | None = None):
        super().__init__(parent)
        self.bridge = bridge
        self.history = history
        self.session: ScanSession | None = None
        self.last_session: ScanSession | None = None

    @property
    def running(self) -> bool:
        return self.session is not None

    def start(self, options: ScanOptions) -> None:
        if self.session is not None or not self.bridge.is_connected:
            return

        def on_event(name: str, data: Any) -> None:
            self.bridge.deliver(lambda _r, _e: self.event.emit(name, data))

        session = ScanSession(self.bridge.client, options, on_event=on_event, history=self.history)
        self.session = session

        def done(summary: Any, err: BaseException | None) -> None:
            self.bridge.deliver(lambda _r, _e: self._finish(summary, err))
        session.start(done)
        self.started.emit(options)

    def _finish(self, summary: Any, err: BaseException | None) -> None:
        self.last_session, self.session = self.session, None
        self.finished.emit(summary, err)

    def pause(self) -> None:
        if self.session:
            self.bridge.run_in_thread(self.session.pause, lambda *_: None)

    def resume(self) -> None:
        if self.session:
            self.bridge.run_in_thread(self.session.resume, lambda *_: None)

    def cancel(self) -> None:
        if self.session:
            self.session.cancel()


def definitions_summary() -> tuple[bool, str]:
    active = store.active_set()
    if active is None:
        return False, "No definitions are installed yet. Update them first (Definitions page)."
    try:
        manifest = layout.load_manifest(active)
    except layout.LayoutError:
        return False, "The active definition set is damaged. Update or roll back on the Definitions page."
    yara = (manifest.get("yara") or {}).get("rules") or 0
    hashes = (manifest.get("hashes") or {}).get("malware_count") or 0
    clam = len((manifest.get("clamav") or {}).get("files", []))
    created = manifest.get("created", 0)
    return True, (f"Definitions from {fmt.iso(created)} ({fmt.age(created)}): "
                  f"{yara} YARA rules, {hashes} hashes, {clam} ClamAV files"
                  + (" + system ClamAV" if (manifest.get("clamav") or {}).get("official") else ""))


class ScanPage(QtWidgets.QWidget):
    start_requested = Signal(object)          # ScanOptions
    show_definitions = Signal()
    choose_drives = Signal()

    def __init__(self, settings: Settings, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.settings = settings
        self.volumes: list[dict[str, Any]] = []
        defaults = settings.data.get("scan", {})
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(heading("Scan"))

        targets = QtWidgets.QGroupBox("Volumes")
        tl = QtWidgets.QVBoxLayout(targets)
        self.targets_label = plain_label("No volumes selected.")
        self.targets_label.setAccessibleName("Selected volumes")
        tl.addWidget(self.targets_label)
        tl.addWidget(button("C&hoose on the Drives page…", self.choose_drives.emit, ("drive-harddisk",)),
                     0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(targets)

        mode = QtWidgets.QGroupBox("What to scan")
        ml = QtWidgets.QVBoxLayout(mode)
        self.quick = QtWidgets.QRadioButton("&Quick: programs, scripts, macro documents and risky folders")
        self.full = QtWidgets.QRadioButton("&Full: every file")
        self.custom = QtWidgets.QRadioButton("Only these &folders or files:")
        self.paths = QtWidgets.QLineEdit()
        self.paths.setPlaceholderText("/Users/name/Downloads; /home/name")
        self.paths.setAccessibleName("Paths to scan, separated by semicolons")
        for radio in (self.quick, self.full, self.custom):
            ml.addWidget(radio)
        ml.addWidget(self.paths)
        {"full": self.full, "custom": self.custom}.get(defaults.get("mode"), self.quick).setChecked(True)
        self.custom.toggled.connect(self.paths.setEnabled)
        self.paths.setEnabled(self.custom.isChecked())
        layout.addWidget(mode)

        engines = QtWidgets.QGroupBox("Engines and checks")
        el = QtWidgets.QGridLayout(engines)
        self.engine_boxes: dict[str, QtWidgets.QCheckBox] = {}
        for i, name in enumerate(ENGINES):
            box = QtWidgets.QCheckBox(ENGINE_NAMES[name])
            box.setChecked(name in defaults.get("engines", ENGINES))
            self.engine_boxes[name] = box
            el.addWidget(box, 0, i)
        self.persistence = QtWidgets.QCheckBox("&Autostart and persistence (registry, tasks, cron, systemd…)")
        self.persistence.setChecked(defaults.get("persistence", True))
        self.integrity = QtWidgets.QCheckBox("Installed &packages and system files (Linux)")
        self.integrity.setChecked(defaults.get("integrity", True))
        self.pua = QtWidgets.QCheckBox("Also report potentially &unwanted programs")
        self.pua.setChecked(bool(defaults.get("detect_pua", False)))
        el.addWidget(self.persistence, 1, 0, 1, 3)
        el.addWidget(self.integrity, 2, 0, 1, 3)
        el.addWidget(self.pua, 3, 0, 1, 3)
        self.tool_boxes: dict[str, QtWidgets.QCheckBox] = {}
        tools_cfg = settings.data.get("tools", {})
        for row, (tool, label) in enumerate(TOOL_NAMES.items(), start=4):
            found = external.find_tool(tool, (tools_cfg.get(tool) or {}).get("path"))
            box = QtWidgets.QCheckBox(f"Run {label}" + ("" if found else " (not installed)"))
            box.setEnabled(found is not None)
            box.setChecked(found is not None and tool in defaults.get("tools", []))
            self.tool_boxes[tool] = box
            el.addWidget(box, row, 0, 1, 3)
        layout.addWidget(engines)

        limits = QtWidgets.QGroupBox("Limits")
        limits.setCheckable(True)
        limits.setChecked(False)
        limits.setToolTip("Defaults suit most drives")
        ll = QtWidgets.QFormLayout(limits)
        self.max_file = QtWidgets.QSpinBox()
        self.max_file.setRange(1, 4096)
        self.max_file.setSuffix(" MiB")
        self.max_file.setValue(int(defaults.get("max_file_size", 100 << 20)) >> 20)
        self.max_scan = QtWidgets.QSpinBox()
        self.max_scan.setRange(1, 4096)
        self.max_scan.setSuffix(" MiB")
        self.max_scan.setValue(int(defaults.get("max_scan_size", 400 << 20)) >> 20)
        self.depth = QtWidgets.QSpinBox()
        self.depth.setRange(0, 64)
        self.depth.setValue(int(defaults.get("archive_depth", 17)))
        self.workers = QtWidgets.QSpinBox()
        self.workers.setRange(0, 64)
        self.workers.setSpecialValueText("automatic")
        self.workers.setValue(int(defaults.get("workers", 0)))
        for text, widget in (("Largest file scanned &fully:", self.max_file),
                             ("Data scanned &per file (archives):", self.max_scan),
                             ("Archive &nesting:", self.depth), ("Parallel &workers:", self.workers)):
            label = QtWidgets.QLabel(text)
            label.setBuddy(widget)
            widget.setAccessibleName(text.replace("&", "").rstrip(":"))
            ll.addRow(label, widget)
        layout.addWidget(limits)

        self.defs_label = plain_label("")
        self.defs_button = button("Update &definitions…", self.show_definitions.emit,
                                  ("system-software-update",))
        dl = QtWidgets.QHBoxLayout()
        dl.addWidget(self.defs_label, 1)
        dl.addWidget(self.defs_button)
        layout.addLayout(dl)
        layout.addStretch(1)
        self.start_button = button("&Start scan", self._start, ("media-playback-start",), default=True)
        self.start_button.setShortcut(QtGui.QKeySequence("Ctrl+Return"))
        row = QtWidgets.QHBoxLayout()
        row.addStretch(1)
        row.addWidget(self.start_button)
        layout.addLayout(row)
        self.refresh_definitions()

    def refresh_definitions(self) -> None:
        ok, text = definitions_summary()
        self.defs_label.setText(text)
        self.defs_button.setVisible(not ok)
        self.start_button.setEnabled(ok and bool(self.volumes))

    def set_volumes(self, volumes: list[dict[str, Any]]) -> None:
        self.volumes = [v for v in volumes if v.get("role") == "filesystem"]
        if not self.volumes:
            self.targets_label.setText("No volumes selected. Tick them on the Drives page.")
        else:
            lines = []
            for v in self.volumes:
                os_name = (v.get("os") or {}).get("name")
                lines.append(f"{v['device']}  {fmt.size(v.get('size'))}  {v.get('fstype') or ''}"
                             + (f"  ({os_name})" if os_name else "")
                             + (f"  “{v['label']}”" if v.get("label") else ""))
            self.targets_label.setText(safe_text("\n".join(lines)))
        self.refresh_definitions()

    def options(self) -> ScanOptions:
        mode = "full" if self.full.isChecked() else "custom" if self.custom.isChecked() else "quick"
        paths = [p.strip() for p in self.paths.text().split(";") if p.strip()] if mode == "custom" else []
        limits = Limits(max_file_size=self.max_file.value() << 20, max_scan_size=self.max_scan.value() << 20,
                        archive_depth=self.depth.value())
        limits.max_hash_size = max(limits.max_hash_size, limits.max_file_size)
        opts = ScanOptions(volumes=[v["id"] for v in self.volumes], mode=mode, paths=paths,
                           engines=[n for n, box in self.engine_boxes.items() if box.isChecked()],
                           limits=limits, workers=self.workers.value(), detect_pua=self.pua.isChecked(),
                           persistence=self.persistence.isChecked(), integrity=self.integrity.isChecked(),
                           tools=[t for t, box in self.tool_boxes.items() if box.isChecked()])
        opts.validate()
        return opts

    def _start(self) -> None:
        try:
            opts = self.options()
        except ValueError as exc:
            error(self, "Cannot start the scan", str(exc))
            return
        scan = self.settings.data.setdefault("scan", {})
        scan.update(mode=opts.mode, engines=opts.engines, persistence=opts.persistence,
                    integrity=opts.integrity, tools=opts.tools, detect_pua=opts.detect_pua,
                    workers=opts.workers)
        self.settings.save()
        self.start_requested.emit(opts)


PHASES = {"loading": "Loading definitions", "persistence": "Checking autostart entries",
          "scanning": "Scanning files", "integrity": "Checking installed packages",
          "tools": "Running extra tools"}


class ProgressPage(QtWidgets.QWidget):
    show_results = Signal()

    def __init__(self, controller: ScanController, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.controller = controller
        self.paused = False
        self.started_at = 0.0
        self.findings = 0
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(heading("Progress"))
        self.phase = plain_label("No scan is running.")
        self.phase.setAccessibleName("Scan phase")
        layout.addWidget(self.phase)
        self.bar = QtWidgets.QProgressBar()
        self.bar.setAccessibleName("Scan progress")
        self.bar.setRange(0, 1)
        self.bar.setValue(0)
        layout.addWidget(self.bar)
        grid = QtWidgets.QFormLayout()
        self.stats: dict[str, QtWidgets.QLabel] = {}
        for key, title in (("files", "Files"), ("data", "Data"), ("rate", "Speed"), ("eta", "Time left"),
                           ("elapsed", "Elapsed"), ("found", "Found"), ("errors", "Unreadable files"),
                           ("current", "Now")):
            label = plain_label("–", wrap=key == "current")
            label.setAccessibleName(title)
            self.stats[key] = label
            grid.addRow(f"{title}:", label)
        layout.addLayout(grid)
        layout.addWidget(plain_label("Found so far:"))
        self.live = QtWidgets.QListWidget()
        self.live.setAccessibleName("Findings so far")
        self.live.itemActivated.connect(lambda _item: self.show_results.emit())
        layout.addWidget(self.live, 1)
        row = QtWidgets.QHBoxLayout()
        self.pause_button = button("&Pause", self._pause, ("media-playback-pause",))
        self.cancel_button = button("&Cancel scan", self._cancel, ("process-stop", "dialog-cancel"))
        self.results_button = button("Show &results", self.show_results.emit, ("view-list-details",),
                                     default=True)
        self.results_button.setEnabled(False)
        row.addWidget(self.pause_button)
        row.addWidget(self.cancel_button)
        row.addStretch(1)
        row.addWidget(self.results_button)
        layout.addLayout(row)
        self._set_running(False)
        controller.started.connect(self._on_started)
        controller.event.connect(self._on_event)
        controller.finished.connect(self._on_finished)

    def _set_running(self, running: bool) -> None:
        self.pause_button.setEnabled(running)
        self.cancel_button.setEnabled(running)

    def _on_started(self, _options: ScanOptions) -> None:
        self.live.clear()
        self.findings = 0
        self.started_at = time.time()
        self.paused = False
        self.pause_button.setText("&Pause")
        self.results_button.setEnabled(False)
        self.bar.setRange(0, 0)
        self.phase.setText("Starting…")
        for label in self.stats.values():
            label.setText("–")
        self._set_running(True)

    def _on_event(self, name: str, data: Any) -> None:
        if name == "scan.status" and isinstance(data, dict):
            text = PHASES.get(data.get("phase", ""), "")
            message = safe(data.get("message", ""), 300)
            self.phase.setText(message or text)
            if data.get("total"):
                self.bar.setRange(0, int(data["total"]))
                self.bar.setValue(int(data.get("done", 0)))
            elif data.get("phase") in ("loading", "persistence", "integrity", "tools"):
                self.bar.setRange(0, 0)
        elif name == "scan.progress" and isinstance(data, dict):
            total = data.get("files_total") or 0
            done = data.get("files_done", 0)
            if total and self.bar.maximum() != total:
                self.bar.setRange(0, int(total))
            if total:
                self.bar.setValue(min(int(done), int(total)))
            counted = data.get("files_counted")
            self.stats["files"].setText(f"{done} of {total}" if total else
                                        f"{done} (counting… {counted})" if counted else str(done))
            self.stats["data"].setText(fmt.size(data.get("bytes_done", 0)))
            self.stats["rate"].setText(f"{data.get('rate_files', 0):.0f} files/s, "
                                       f"{fmt.size(data.get('rate_bytes', 0))}/s")
            self.stats["eta"].setText(fmt.duration(data["eta"]) if data.get("eta") is not None else "–")
            self.stats["elapsed"].setText(fmt.duration(data.get("elapsed", 0)))
            self.stats["errors"].setText(str(data.get("errors", 0)))
            self.stats["current"].setText(safe(names.display(data.get("current", ""), 200), 300))
            self.paused = bool(data.get("paused"))
        elif name == "scan.detection" and isinstance(data, dict):
            try:
                det = Detection.from_dict(data)
            except TypeError:
                return
            if det.inventory:
                return
            self.findings += 1
            self.stats["found"].setText(str(self.findings))
            where = det.details.get("location") if det.engine in CHECK_ENGINES else det.path
            item = QtWidgets.QListWidgetItem(severity_icon(det.severity),
                                             f"{safe(det.signature, 200)} — {det.volume}:{safe(where, 300)}")
            item.setToolTip(det.severity)
            self.live.insertItem(0, item)
            while self.live.count() > 500:
                self.live.takeItem(self.live.count() - 1)

    def _on_finished(self, summary: Any, err: Any) -> None:
        self._set_running(False)
        self.bar.setRange(0, 1)
        self.bar.setValue(1)
        self.results_button.setEnabled(True)
        if err is not None:
            self.phase.setText(f"The scan could not run: {safe(err, 500)}")
            return
        state = summary.get("state")
        verdict = {"finished": "Scan finished", "cancelled": "Scan cancelled", "failed": "Scan failed"}.get(
            state, str(state))
        found = summary.get("detections", 0)
        self.phase.setText(f"{verdict}: {summary.get('files_scanned', 0)} files scanned in "
                           f"{fmt.duration(summary.get('finished', 0) - summary.get('started', 0))}, "
                           f"{found} finding{'s' if found != 1 else ''}"
                           + (f". {safe(summary['message'], 300)}" if summary.get("message") else ""))

    def _pause(self) -> None:
        if self.paused:
            self.controller.resume()
            self.pause_button.setText("&Pause")
        else:
            self.controller.pause()
            self.pause_button.setText("&Resume")
        self.paused = not self.paused

    def _cancel(self) -> None:
        self.controller.cancel()
        self.phase.setText("Cancelling…")
        self.cancel_button.setEnabled(False)
