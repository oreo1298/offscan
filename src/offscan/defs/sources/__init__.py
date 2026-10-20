"""Registry of definition sources (order = order shown in the UI)."""

from __future__ import annotations

from ...settings import Settings
from .base import Source, SourceInfo
from .clamav import (
    ClamAVOfficial,
    LinuxMalwareDetect,
    SanesecurityEmail,
    SanesecurityMalware,
    SecuriteInfo,
    URLhaus,
)
from .hashes import NSRL, ESETMalwareIOC, LOLDrivers, MalShare, MalwareBazaar, ThreatFox
from .yara import (
    BartblazeRules,
    ElasticRules,
    ReversingLabsRules,
    SignatureBase,
    YaraForge,
    YARAify,
    YaraRulesProject,
)

SOURCE_CLASSES: tuple[type[Source], ...] = (
    ClamAVOfficial, SanesecurityMalware, LinuxMalwareDetect, SanesecurityEmail, SecuriteInfo, URLhaus,
    YaraForge, BartblazeRules, ElasticRules, SignatureBase, ReversingLabsRules, YaraRulesProject,
    YARAify,
    LOLDrivers, ESETMalwareIOC, MalwareBazaar, ThreatFox, MalShare,
    NSRL,
)


def all_sources(settings: Settings) -> list[Source]:
    return [cls(settings) for cls in SOURCE_CLASSES]


def by_id(settings: Settings) -> dict[str, Source]:
    return {s.id: s for s in all_sources(settings)}


__all__ = ["SOURCE_CLASSES", "Source", "SourceInfo", "all_sources", "by_id"]
