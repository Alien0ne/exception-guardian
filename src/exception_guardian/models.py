"""Common records shared by readers, enrichment, grading and guard."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum


class RuleType(StrEnum):
    ACCEPT = "accept"
    RECAST = "recast"
    EXCLUSION = "exclusion"


class Grade(StrEnum):
    OK = "OK"
    REVIEW = "REVIEW"
    REVOKE = "REVOKE"

    @property
    def rank(self) -> int:
        return {"OK": 0, "REVIEW": 1, "REVOKE": 2}[self.value]


@dataclass(frozen=True)
class RiskException:
    source: str
    rule_id: str
    rule_type: RuleType
    cves: tuple[str, ...]
    plugin_ids: tuple[str, ...]
    targets: tuple[str, ...]
    original_severity: str | None
    new_severity: str | None
    owner: str | None
    created: date
    updated: date | None
    expires: date | None
    justification: str
    status: str  # "enabled" | "disabled"
    revised_findings: int | None
    raw: dict = field(default_factory=dict, compare=False, hash=False)
    revised_findings_capped: bool = False  # the live count stopped at its page cap: "at least revised_findings"


@dataclass(frozen=True)
class Asset:
    id: str
    name: str
    os: str | None
    ips: tuple[str, ...]
    fqdns: tuple[str, ...]
    tags: tuple[str, ...]
    internet_facing: bool
    exposure_since: date | None
    critical: bool | None
    on_attack_path: bool | None
    public_ips: tuple[str, ...] = ()  # globally routable addresses: a hint of exposure, not proof
    origin: str = "hosts"  # where it was read: "hosts" (/assets or a fixture), "host-search" (v3, no tags), "webapp"
    exposure_reason: str = ""  # why internet_facing is true: "tag Zone:DMZ", "internet range ...", "host list ..."
    tenable_public: bool | None = None  # Tenable's own is_public flag (v3 host search): a hint, like a public IP
    acr: float | None = None  # Tenable Asset Criticality Rating, 1-10 (Tenable One inventory or VM asset)
    aes: float | None = None  # Tenable Asset Exposure Score, 0-1000
    attack_paths: int | None = None  # Tenable One attack path analysis: paths through this asset
    critical_paths: int | None = None
    context_source: str = ""  # where acr/aes/paths came from, cited in the report
    public_dns: tuple[str, ...] = ()  # verified public DNS names (map-exposure): a hint, like a public IP


@dataclass(frozen=True)
class CveIntel:
    cve: str
    in_kev: bool
    kev_date_added: date | None
    kev_ransomware: bool
    epss_now: float | None
    epss_at_created: float | None
    source: str  # "live" | "snapshot:YYYY-MM-DD"
    epss_then_source: str | None = None  # set when only the value at acceptance came from the snapshot


@dataclass(frozen=True)
class Trigger:
    code: str
    grade: Grade
    then: str | None
    now: str
    source: str


@dataclass(frozen=True)
class GradedException:
    exception: RiskException
    grade: Grade
    triggers: tuple[Trigger, ...]
    assets: tuple[Asset, ...]
    intel: tuple[CveIntel, ...]
    notes: tuple[str, ...]
