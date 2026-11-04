"""guardian.yaml loading. Missing keys fall back to the defaults below."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

KNOWN_TARGETS = ("splunk", "sentinel", "defender")


@dataclass(frozen=True)
class SourceConfig:
    name: str
    params: dict


@dataclass(frozen=True)
class ExposureConfig:
    """What marks an asset internet-facing (REVOKE). Tags are the company's own names; ranges and a host list
    cover what tags miss (hosts behind NAT or a load balancer have only a private IP)."""
    internet_tags: tuple[str, ...] = ()  # no tag name is assumed: each company names its own
    internet_ranges: tuple[str, ...] = ()
    internet_hosts_file: str | None = None
    claims_file: str | None = None  # verified agent findings (map-exposure step)


@dataclass(frozen=True)
class Config:
    revoke_epss: float = 0.5
    review_max_age_days: int = 365
    review_epss_delta: float = 0.1
    internal_keywords: tuple[str, ...] = (
        "internal", "not internet", "no external", "isolated", "air-gapped", "intranet")
    sources: tuple[SourceConfig, ...] = ()
    assets: dict = field(default_factory=dict)
    siem_targets: tuple[str, ...] = KNOWN_TARGETS
    offline: bool = False
    intel_snapshot_dir: str = "samples/intel"
    sample_logs_dir: str = ""  # your own sample logs; the demo config points at samples/logs
    exposure: ExposureConfig = ExposureConfig()
    max_context_lookups: int = 1500  # Tenable One assets looked up per run (8 at a time)
    critical_acr: float = 9  # Tenable ACR (1-10) at or above this marks a critical asset (ATTACK_PATH, REVOKE)
    placeholders: dict = field(default_factory=dict)  # SigmaHQ %NAME% → your own values, e.g. DC-MACHINE-NAME


KNOWN_KEYS = ("revoke_epss", "review_epss_delta", "review_max_age_days", "internal_keywords", "sources", "assets",
              "siem_targets", "offline", "intel_snapshot_dir", "sample_logs_dir", "max_context_lookups", "critical_acr",
              "exposure", "placeholders", "placeholders_file")


def _num(data: dict, key: str, kind):
    try:
        return kind(data[key])
    except (TypeError, ValueError):
        raise ValueError(f"{key}: {data[key]!r} is not a {'number' if kind is float else 'whole number'}") from None


def _items(value, key: str) -> tuple[str, ...]:
    """A list key. One string is one item (`internet_tags: Exposure:Internet`), never a run of letters."""
    if value is None:
        return ()
    if isinstance(value, (str, int, float)):
        return (str(value),)
    if not isinstance(value, list):
        raise ValueError(f"{key}: give a list, e.g. {key}: [a, b]")
    return tuple(str(v) for v in value)


def _map(value, key: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{key}: give a map of keys, not a {type(value).__name__} (see guardian.yaml)")
    return dict(value)


def _placeholder_map(ph, where: str) -> dict:
    if not ph:
        return {}
    if not isinstance(ph, dict):
        raise ValueError(f"{where}: give a map of placeholder name to values, e.g. "
                         "placeholders: {DC-MACHINE-NAME: [DC01$, DC02$]}")
    return {str(k).strip("%"): tuple(str(x) for x in (v if isinstance(v, list) else [v]))
            for k, v in ph.items() if v not in (None, "", [])}


def load_config(path: str | Path) -> Config:
    try:
        data = yaml.safe_load(Path(path).read_text()) or {}
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        raise ValueError(f"{path} is not valid YAML" + (f" (line {mark.line + 1})" if mark else "")
                         + f": {getattr(exc, 'problem', None) or exc}") from None
    if not isinstance(data, dict):
        raise ValueError(f"{path}: a config is a set of keys (see guardian.yaml), not a {type(data).__name__}")
    unknown = sorted(str(k) for k in data if k not in KNOWN_KEYS)
    if unknown:
        raise ValueError(f"{path}: unknown key{'s' if len(unknown) > 1 else ''} {', '.join(unknown)}. Known keys: "
                         f"{', '.join(KNOWN_KEYS)}")
    if "sources" in data and not data["sources"]:
        raise ValueError(f"{path}: no sources: list at least one under sources (see guardian.yaml)")
    kw: dict = {}
    for key in ("revoke_epss", "review_epss_delta"):
        if key in data:
            kw[key] = _num(data, key, float)
    if "review_max_age_days" in data:
        kw["review_max_age_days"] = _num(data, "review_max_age_days", int)
    if "internal_keywords" in data:
        kw["internal_keywords"] = tuple(k.lower() for k in _items(data["internal_keywords"], "internal_keywords"))
    if "sources" in data:
        if not isinstance(data["sources"], list):
            raise ValueError("sources: give a list, e.g. sources: [{name: tenable-vm}] (see guardian.yaml)")
        srcs = []
        for i, s in enumerate(data["sources"], 1):
            if not isinstance(s, dict):
                raise ValueError(f"sources: entry {i} is not a map: give it a name, e.g. - name: tenable-vm")
            s = dict(s)
            if not s.get("name"):
                raise ValueError(f"sources: entry {i} has no name (tenable-vm, tenable-sc or csv)")
            srcs.append(SourceConfig(name=str(s.pop("name")), params=s))
        if sum(1 for x in srcs if x.name == "tenable-sc") > 1:  # their rules and repository ids would mix
            raise ValueError("only one Security Center source per config: its rules carry no instance name, so "
                             "hosts and repositories from two instances would be mixed. Use one config per instance")
        kw["sources"] = tuple(srcs)
    if "assets" in data:
        kw["assets"] = _map(data["assets"], "assets")
    if "siem_targets" in data:
        targets = _items(data["siem_targets"], "siem_targets")
        unknown = [t for t in targets if t not in KNOWN_TARGETS]
        if unknown:
            raise ValueError(f"unknown siem_targets {unknown}; known: {list(KNOWN_TARGETS)}")
        kw["siem_targets"] = targets
    if "offline" in data:
        kw["offline"] = bool(data["offline"])
    if "intel_snapshot_dir" in data:
        kw["intel_snapshot_dir"] = str(data["intel_snapshot_dir"])
    if "sample_logs_dir" in data:
        kw["sample_logs_dir"] = str(data["sample_logs_dir"])
    if "max_context_lookups" in data:
        kw["max_context_lookups"] = max(0, _num(data, "max_context_lookups", int))
    if "critical_acr" in data:
        kw["critical_acr"] = _num(data, "critical_acr", float)
    ph = _placeholder_map(data.get("placeholders"), "placeholders")
    if data.get("placeholders_file"):
        # your own values (DC addresses) in a file kept out of git; it wins over the config. Missing: stand-ins stay
        f = Path(str(data["placeholders_file"]))
        f = f if f.is_absolute() else Path(path).parent / f
        if f.is_file():
            ph.update(_placeholder_map(yaml.safe_load(f.read_text()), f"placeholders_file {f.name}"))
    if ph:
        kw["placeholders"] = ph
    if data.get("exposure"):
        ex, base = _map(data["exposure"], "exposure"), Path(path).parent
        rel = lambda v: str(v) if Path(str(v)).is_absolute() or Path(str(v)).exists() else str(base / str(v))  # noqa: E731
        kw["exposure"] = ExposureConfig(
            internet_tags=_items(ex.get("internet_tags"), "exposure.internet_tags"),
            internet_ranges=_items(ex.get("internet_ranges"), "exposure.internet_ranges"),
            internet_hosts_file=rel(ex["internet_hosts_file"]) if ex.get("internet_hosts_file") else None,
            claims_file=rel(ex["claims_file"]) if ex.get("claims_file") else None)
    return Config(**kw)
