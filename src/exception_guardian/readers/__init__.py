"""Reader registry. A reader is `read(params: dict) -> list[RiskException]` registered under a name."""
from __future__ import annotations

import sys
from importlib import import_module
from typing import Callable

from ..config import SourceConfig
from ..models import RiskException, RuleType

Reader = Callable[[dict], list[RiskException]]
_REGISTRY: dict[str, Reader] = {}
_BUILTIN = ("tenable_vm", "tenable_sc", "csv_reader")


def register(name: str) -> Callable[[Reader], Reader]:
    def deco(fn: Reader) -> Reader:
        _REGISTRY[name] = fn
        return fn
    return deco


def _load_builtins() -> None:
    for mod in _BUILTIN:
        import_module(f"{__name__}.{mod}")


def get_reader(name: str) -> Reader:
    _load_builtins()
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown reader {name!r}; known readers: {sorted(_REGISTRY)}") from None


def read_all(sources: tuple[SourceConfig, ...]) -> tuple[list[RiskException], list[str]]:
    exceptions: list[RiskException] = []
    warnings: list[str] = []
    for src in sources:
        try:
            reader = get_reader(src.name)
            exceptions.extend(reader(src.params))
            warnings.extend(getattr(sys.modules.get(reader.__module__), "LAST_WARNINGS", []))
        except Exception as exc:  # one bad source must not sink the run
            status = getattr(getattr(exc, "response", None), "status_code", None)
            hint = (" (HTTP 403: the API user's role is not allowed to read this; ask the tenant admin for read access)"
                    if status == 403 else "")
            warnings.append(f"source {src.name} failed: {exc}{hint}")
    return exceptions, warnings


def enrich_plugin_cves(exceptions: list[RiskException], lookup, webapp_lookup=None) -> tuple[list[RiskException], list[str]]:
    """Fill CVEs for plugin-only rules from the scanner's own plugin details (one lookup per plugin). Rules on web
    apps (resource_type WEBAPP) use webapp_lookup when given: their plugins live in a different catalogue."""
    from dataclasses import replace as _replace

    from ..parallel import parallel_map

    def kind_of(e: RiskException):
        web = webapp_lookup is not None and e.raw.get("resource_type") == "WEBAPP"
        return (webapp_lookup, "web app plugin") if web else (lookup, "plugin")

    todo = [e for e in exceptions if not e.cves and e.plugin_ids]
    keys = list(dict.fromkeys((kind_of(e)[1], pid) for e in todo for pid in e.plugin_ids))  # each plugin once
    fns = {kind: fn for e in todo for fn, kind in [kind_of(e)]}
    source = todo[0].source if todo else ""
    found = dict(zip(keys, parallel_map(lambda k: tuple(fns[k[0]](k[1])), keys, label=f"{source} plugin CVEs")))
    warnings: list[str] = []
    out = []
    for e in exceptions:
        if e.cves or not e.plugin_ids:
            out.append(e)
            continue
        kind = kind_of(e)[1]
        cves: list[str] = []
        for pid in e.plugin_ids:
            got = found[(kind, pid)]
            if isinstance(got, Exception):
                warnings.append(f"source {e.source} ({kind} CVEs) failed: {kind} {pid} CVE lookup failed ({got}), so "
                                f"rule {e.rule_id} was graded without that plugin's CVEs")
                continue
            cves += [c for c in got if c not in cves]
        out.append(_replace(e, cves=tuple(cves)) if cves else e)
    return out, warnings


def count_rule_findings(exceptions: list[RiskException], counter) -> tuple[list[RiskException], list[str]]:
    """Fill revised_findings (how many findings disabling the rule re-surfaces) for enabled accept/recast rules
    that do not carry it. counter(raw_rule) -> (count, capped). A failed count is a warning; the count stays unknown."""
    from dataclasses import replace as _replace

    from ..parallel import parallel_map
    todo = [e for e in exceptions if e.revised_findings is None and e.status == "enabled"
            and e.rule_type in (RuleType.ACCEPT, RuleType.RECAST)]
    counts = dict(zip(map(id, todo), parallel_map(lambda e: counter(e.raw), todo,
                                                  label=f"{todo[0].source if todo else ''} finding counts")))
    warnings: list[str] = []
    out = []
    for e in exceptions:
        got = counts.get(id(e))
        if got is None:
            out.append(e)
        elif isinstance(got, Exception):
            warnings.append(f"{e.source}: finding count for rule {e.rule_id} failed: {got}")
            out.append(e)
        else:
            n, capped = got
            out.append(_replace(e, revised_findings=n, revised_findings_capped=capped))
    return out, warnings
