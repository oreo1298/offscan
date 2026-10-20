"""YARA-X (preferred) or classic YARA, behind one small interface.

Compiled rules are always produced locally by our own compiler step (never
loaded from a third party: YARA-X warns that deserialising untrusted
compiled rules is unsafe) and cached per engine version.

Rule sets that expect THOR/LOKI-style external variables (signature-base)
get them defined at compile time with empty defaults and set per file.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

EXTERNALS = ("filename", "filepath", "extension", "filetype", "owner")


class YaraUnavailable(Exception):
    pass


def engine_name() -> str | None:
    try:
        import yara_x  # noqa: F401
        return "yara-x"
    except ImportError:
        pass
    try:
        import yara  # noqa: F401
        return "yara"
    except ImportError:
        return None


def engine_version(name: str | None = None) -> str | None:
    name = name or engine_name()
    try:
        if name == "yara-x":
            import yara_x
            return getattr(yara_x, "__version__", None) or _dist_version("yara-x")
        if name == "yara":
            import yara
            return yara.__version__
    except ImportError:
        return None
    return None


def _dist_version(dist: str) -> str | None:
    try:
        from importlib.metadata import version
        return version(dist)
    except Exception:
        return None


@dataclass
class CompileResult:
    engine: str
    version: str | None
    rules: int
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)


def compile_sources(sources: list[tuple[str, str, str]], output: Path,
                    engine: str | None = None) -> CompileResult:
    """Compile ``sources`` = [(namespace, origin, text)] into ``output``.

    Each source file is first compiled on its own so one broken file is
    skipped (and reported) instead of failing the whole set.
    """
    engine = engine or engine_name()
    if engine == "yara-x":
        return _compile_yara_x(sources, output)
    if engine == "yara":
        return _compile_yara(sources, output)
    raise YaraUnavailable("neither yara-x nor yara-python is installed")


def _yx_compiler(yara_x: Any) -> Any:
    try:
        compiler = yara_x.Compiler(relaxed_re_syntax=True)
    except TypeError:
        compiler = yara_x.Compiler()
    for ident in EXTERNALS:
        compiler.define_global(ident, "")
    for module in ("magic", "cuckoo", "androguard"):
        try:
            compiler.ignore_module(module)
        except Exception:
            pass
    return compiler


def _compile_yara_x(sources: list[tuple[str, str, str]], output: Path) -> CompileResult:
    import yara_x
    result = CompileResult("yara-x", engine_version("yara-x"), 0)
    good: list[tuple[str, str, str]] = []
    for namespace, origin, text in sources:
        probe = _yx_compiler(yara_x)
        try:
            probe.new_namespace(namespace)
            probe.add_source(text, origin=origin)
            good.append((namespace, origin, text))
        except yara_x.CompileError as exc:
            result.skipped_files.append(origin)
            result.errors.append(f"{origin}: {str(exc).splitlines()[0][:300]}")
    compiler = _yx_compiler(yara_x)
    namespace = None
    for ns, origin, text in good:
        if ns != namespace:
            compiler.new_namespace(ns)
            namespace = ns
        try:
            compiler.add_source(text, origin=origin)
        except yara_x.CompileError as exc:   # e.g. duplicate rule names across files
            result.skipped_files.append(origin)
            result.errors.append(f"{origin}: {str(exc).splitlines()[0][:300]}")
    try:
        result.warnings = [str(w.get("title", w)) if isinstance(w, dict) else str(w)
                           for w in compiler.warnings()][:500]
    except Exception:
        pass
    rules = compiler.build()
    tmp = output.with_suffix(output.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        rules.serialize_into(fh)
    os.replace(tmp, output)
    result.rules = _count_rules_yx(rules, sources, good)
    return result


_RULE_RE = re.compile(rb"^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+[A-Za-z_]", re.M)


def count_rules(text: str) -> int:
    return len(_RULE_RE.findall(text.encode("utf-8", "replace")))


def _count_rules_yx(rules: Any, sources: list, good: list) -> int:
    return sum(count_rules(text) for _, _, text in good)


def _compile_yara(sources: list[tuple[str, str, str]], output: Path) -> CompileResult:
    import yara
    result = CompileResult("yara", engine_version("yara"), 0)
    externals = dict.fromkeys(EXTERNALS, "")
    good: dict[str, str] = {}
    for namespace, origin, text in sources:
        try:
            yara.compile(source=text, externals=externals)
        except yara.Error as exc:
            result.skipped_files.append(origin)
            result.errors.append(f"{origin}: {str(exc)[:300]}")
            continue
        key = f"{namespace}:{len(good)}"
        good[key] = text
    rules = yara.compile(sources=good, externals=externals)
    tmp = output.with_suffix(output.suffix + ".tmp")
    rules.save(str(tmp))
    os.replace(tmp, output)
    result.rules = sum(1 for _ in rules)
    return result


def compiled_filename(engine: str) -> str:
    return "rules.yarx" if engine == "yara-x" else "rules.yarc"


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    meta: dict[str, Any]
    tags: list[str]


class Scanner:
    """Loaded rules ready to scan byte buffers (one per worker process)."""

    def __init__(self, path: Path, engine: str, timeout: int = 60):
        self.engine = engine
        self.timeout = timeout
        if engine == "yara-x":
            import yara_x
            with open(path, "rb") as fh:
                self._rules = yara_x.Rules.deserialize_from(fh)
            self._scanner = yara_x.Scanner(self._rules)
            self._scanner.set_timeout(int(timeout))
            self._yx = yara_x
        elif engine == "yara":
            import yara
            self._rules = yara.load(str(path))
            self._yara = yara
        else:
            raise YaraUnavailable(engine)

    def scan(self, data: bytes, path: str = "", owner: str = "") -> list[YaraMatch]:
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1].lstrip(".").lower()
        values = {"filename": name, "filepath": os.path.dirname(path), "extension": ext,
                  "filetype": "", "owner": owner}
        if self.engine == "yara-x":
            for key, value in values.items():
                try:
                    self._scanner.set_global(key, value)
                except Exception:
                    pass
            results = self._scanner.scan(data)
            out = []
            for rule in results.matching_rules:
                meta = {}
                for item in rule.metadata:
                    key, value = item[0], item[1]
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", "replace")
                    meta[key] = value
                out.append(YaraMatch(rule.identifier, rule.namespace, meta, list(rule.tags)))
            return out
        matches = self._rules.match(data=data, timeout=self.timeout, externals=values)
        return [YaraMatch(m.rule, m.namespace, dict(m.meta), list(m.tags)) for m in matches]

    @property
    def timeout_error(self) -> type[BaseException]:
        if self.engine == "yara-x":
            return self._yx.TimeoutError
        return self._yara.TimeoutError
