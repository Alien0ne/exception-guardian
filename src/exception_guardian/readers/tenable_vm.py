"""Tenable Vulnerability Management: accept/recast rules (POST /v1/recast/rules/search) and scan exclusions."""
from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path

from ..cves import split_cves
from ..models import RiskException, RuleType
from . import register

_ACTIONS = {"ACCEPT": RuleType.ACCEPT, "RECAST": RuleType.RECAST}
_TARGET_PROPS = ("asset.name", "asset.fqdns", "asset.ipv4_addresses", "asset.ipv6_addresses", "asset.id")


def _iso_date(s) -> date | None:
    """ISO text (any offset, converted to UTC) or epoch seconds/milliseconds."""
    if s in (None, ""):
        return None
    if isinstance(s, (int, float)) or str(s).replace(".", "", 1).isdigit():
        if re.fullmatch(r"(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])", str(s)):
            return date(int(str(s)[:4]), int(str(s)[4:6]), int(str(s)[6:]))  # basic ISO 20240101, not epoch
        v = float(s)
        if v <= 0:  # 0 or -1 stands for "no date"
            return None
        return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc).date()
    d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return (d.astimezone(timezone.utc) if d.tzinfo else d).date()


#: Operators that exclude their values: "every asset (or CVE) except these".
NEGATED = {"neq", "nmatch", "not-in", "nin", "not_eq", "ne"}


def _conditions(flt: dict):
    for key in ("and", "or"):
        for cond in flt.get(key, []) or []:
            if "property" in cond:
                yield cond
            else:
                yield from _conditions(cond)


def _values(flt: dict, props: tuple[str, ...], negated: bool = False) -> tuple[str, ...]:
    out: list[str] = []
    for cond in _conditions(flt or {}):
        if cond["property"] in props and (str(cond.get("operator", "")).lower() in NEGATED) == negated:
            v = cond.get("value")
            out.extend(v if isinstance(v, list) else [v])
    return tuple(str(x) for x in out)


ALL_ASSETS = "*"  # target meaning "every asset" (a rule with no asset filter)


def _targets(flt: dict) -> tuple[str, ...]:
    """Targets for match(): names/IPs, 'tag:k:v', '!x' (excluded), '?prop=v' (a property we cannot match)."""
    out = list(_values(flt, _TARGET_PROPS)) + ["!" + v for v in _values(flt, _TARGET_PROPS, negated=True)]
    for cond in _conditions(flt or {}):
        prop = str(cond["property"])
        v = cond.get("value")
        vals = v if isinstance(v, list) else [v]
        neg = "!" if str(cond.get("operator", "")).lower() in NEGATED else ""
        if prop.startswith("tag."):
            out += [f"{neg}tag:{prop[4:]}:{x}" for x in vals]
        elif prop.startswith("asset.") and prop not in _TARGET_PROPS:
            out += [f"{neg}?{prop}={x}" for x in vals]
    return tuple(out) or (ALL_ASSETS,)


def parse_rules(rules: list[dict]) -> list[RiskException]:
    out = []
    for r in rules:
        try:
            x = _rule(r)
        except Exception as exc:  # one malformed rule must not sink every other rule
            LAST_WARNINGS.append(f"source tenable-vm failed: rule {str(r.get('rule_id', '?'))[:60]} skipped "
                                 f"({type(exc).__name__}: {exc})")
            continue
        if x is not None:
            out.append(x)
    return out


def _rule(r: dict) -> RiskException | None:
    rv = r.get("rule_value", {})
    rtype = _ACTIONS.get(rv.get("action", ""))
    if rtype is None:  # CHANGE_RESULT / ACCEPT_RESULT are compliance rules, out of scope
        return None
    flt = r.get("filter", {})
    excluded = list(_values(flt, ("definition.cve",), negated=True))
    raw = {**r, "x_excluded_cves": excluded} if excluded else r
    return RiskException(
        source="tenable-vm", rule_id=str(r["rule_id"]), rule_type=rtype,
        cves=split_cves(_values(flt, ("definition.cve",)))[0], plugin_ids=_values(flt, ("definition.id",)),
        targets=_targets(flt),
        original_severity=rv.get("original_severity"),
        new_severity=rv.get("severity") if rtype is RuleType.RECAST else None,
        owner=r.get("x_owner") or r.get("created_by"),
        created=_need_date(_iso_date(r["created_at"])), updated=_iso_date(r.get("updated_at")),
        expires=_iso_date(r.get("expires_at")),
        justification=str(rv.get("comment") or r.get("description") or ""),
        status="disabled" if (r.get("disabled_details") or {}).get("disabled") else "enabled",
        revised_findings=r.get("x_revised_findings"), raw=raw)


def _need_date(d: date | None) -> date:
    if d is None:
        raise ValueError("missing created date")
    return d


def _epoch_date(v) -> date | None:
    return _iso_date(v)


def _exclusion_expiry(e: dict) -> date | None:
    """A one-off schedule ends; an always-on or recurring exclusion has no end date."""
    s = e.get("schedule") or {}
    if not s.get("enabled") or str((s.get("rrules") or {}).get("freq") or "ONETIME").upper() != "ONETIME":
        return None
    end = str(s.get("endtime") or "").strip()
    return datetime.fromisoformat(end.replace(" ", "T")).date() if end else None


def parse_exclusions(exclusions: list[dict]) -> list[RiskException]:
    out = []
    names = [str(e.get("name") or "") for e in exclusions]
    for e in exclusions:
        name = str(e.get("name") or "")
        rid = f"{name} ({e.get('id')})" if not name or names.count(name) > 1 else name
        try:
            members = tuple(m.strip() for m in str(e.get("members", "")).split(",") if m.strip())
            out.append(RiskException(
                source="tenable-vm", rule_id=rid, rule_type=RuleType.EXCLUSION,
                cves=(), plugin_ids=(), targets=members, original_severity=None, new_severity=None,
                owner=e.get("x_owner"), created=_need_date(_epoch_date(e["creation_date"])),
                updated=_epoch_date(e.get("last_modification_date")), expires=_exclusion_expiry(e),
                justification=str(e.get("description") or ""), status="enabled",
                revised_findings=None, raw=e))
        except Exception as exc:
            LAST_WARNINGS.append(f"source tenable-vm failed: exclusion {rid[:60]} skipped ({type(exc).__name__}: {exc})")
    return out


#: Warnings from the last live read (plugin lookups that failed); read_all collects them.
LAST_WARNINGS: list[str] = []


@register("tenable-vm")
def read(params: dict) -> list[RiskException]:
    LAST_WARNINGS.clear()
    if "fixture_dir" in params:
        d = Path(params["fixture_dir"])
        rules = json.loads((d / "recast_rules.json").read_text())["rules"]
        excl = json.loads((d / "exclusions.json").read_text())["exclusions"]
        return parse_rules(rules) + parse_exclusions(excl)
    if "base_url" in params:
        from ..tenable_client import TenableVMClient
        from . import count_rule_findings, enrich_plugin_cves
        client = TenableVMClient.from_env(params["base_url"])
        rules, warn = enrich_plugin_cves(parse_rules(client.search_rules()), client.plugin_cves, client.was_plugin_cves)
        rules, warn2 = count_rule_findings(rules, client.count_rule_findings)
        LAST_WARNINGS.extend(warn + warn2)
        return rules + parse_exclusions(client.list_exclusions())
    raise ValueError("tenable-vm source needs fixture_dir or base_url")
