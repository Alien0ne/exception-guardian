"""Sigma → SIEM queries. A fresh SigmaCollection per target: pipelines mutate rules in place.

SigmaHQ rules can carry placeholders (`%DC-MACHINE-NAME%`) that only the reader can fill: they are widened to
match any value, and the result says so. Windows event-log rules (service: security) have no ASIM table, so
Sentinel falls back to the Azure Monitor pipeline and its SecurityEvent table; Defender XDR has no such table.
A category ASIM has no table for (image_load, antivirus) uses Defender XDR's Device* tables, which Sentinel holds
when the Microsoft Defender XDR connector streams them."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

_EVENT_TABLES = {"security": "SecurityEvent"}  # Windows event log service → Sentinel table (Azure Monitor)


def _keep_unmatched_values() -> None:
    """pySigma's ReplaceStringTransformation (the Sentinel ASIM and Defender pipelines use it to spell out HKLM)
    rebuilds every registry value from its text, even one its regex does not match. A value ending in a backslash
    under `contains` then reads `...\\*`, an escaped star, and the query becomes `endswith "...*"`, which never
    matches (SigmaHQ's PrintNightmare driver rule, live run 4 Nov 2026). A value the regex does not touch is left as
    it was."""
    from sigma.processing.transformations import ReplaceStringTransformation
    if getattr(ReplaceStringTransformation, "_eg_keeps_unmatched", False):
        return
    original = ReplaceStringTransformation.apply_string_value

    def apply_string_value(self, field, val):
        if not self.skip_special and not self.re.search(str(val)):
            return val
        return original(self, field, val)
    ReplaceStringTransformation.apply_string_value = apply_string_value
    ReplaceStringTransformation._eg_keeps_unmatched = True


def _wild(fill: dict | None = None):
    """Placeholders set in the config (`placeholders:`) become those values; any other one matches anything."""
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import ValueListPlaceholderTransformation, WildcardPlaceholderTransformation
    fill = {k: list(v) for k, v in (fill or {}).items()}
    items = ([ProcessingItem(ValueListPlaceholderTransformation(include=list(fill)))] if fill else [])
    items.append(ProcessingItem(WildcardPlaceholderTransformation()))
    return ProcessingPipeline(items=items, vars=fill, priority=1)


def _splunk(fill=None):
    from sigma.backends.splunk import SplunkBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline
    return SplunkBackend(_wild(fill) + splunk_windows_pipeline())


def _sentinel(fill=None):
    from sigma.backends.kusto import KustoBackend
    _keep_unmatched_values()
    from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
    return KustoBackend(_wild(fill) + sentinel_asim_pipeline())


def _sentinel_events(table: str, fill=None):
    from sigma.backends.kusto import KustoBackend
    _keep_unmatched_values()
    from sigma.pipelines.azuremonitor import azure_monitor_pipeline
    return KustoBackend(_wild(fill) + azure_monitor_pipeline(query_table=table))


def _defender(fill=None):
    from sigma.backends.kusto import KustoBackend
    _keep_unmatched_values()
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
    return KustoBackend(_wild(fill) + microsoft_xdr_pipeline())


def _antivirus(fill=None):
    """Antivirus detections are DeviceEvents rows with ActionType AntivirusDetection; Sigma's Filename (the
    detected file's path) is FolderPath there."""
    from sigma.backends.kusto import KustoBackend
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
    from sigma.processing.conditions import LogsourceCondition
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation
    av = lambda: [LogsourceCondition(category="antivirus")]  # noqa: E731  (pySigma binds each condition once)
    pre = ProcessingPipeline(items=[
        ProcessingItem(AddConditionTransformation({"ActionType": "AntivirusDetection"}), rule_conditions=av()),
        ProcessingItem(FieldMappingTransformation({"Filename": "FolderPath"}), rule_conditions=av())], priority=5)
    return KustoBackend(_wild(fill) + pre + microsoft_xdr_pipeline(query_table="DeviceEvents"))


_KEYWORD = re.compile(r'not\(("(?:[^"\\]|\\.)*")\)')


def _kql_keywords(q: str) -> str:
    """pySigma writes a Sigma keyword filter as not("text"), which KQL rejects; not(* has "text") searches every
    column, as the keyword means."""
    return _KEYWORD.sub(r"not(* has \1)", q)


TARGETS: dict[str, Callable] = {"splunk": _splunk, "sentinel": _sentinel, "defender": _defender}


@dataclass(frozen=True)
class ConvResult:
    ok: bool
    query: str | None
    error: str | None
    note: str | None = None


LABEL = {"splunk": ("Splunk", "SPL"), "sentinel": ("Microsoft Sentinel", "KQL"), "defender": ("Defender XDR", "KQL")}
NAME = {**{t: v[0] for t, v in LABEL.items()}, "sentinel": "Sentinel (ASIM)"}  # in errors: the ASIM schema decides


def _category(yaml_text: str) -> str:
    import yaml
    try:
        return str(((yaml.safe_load(yaml_text) or {}).get("logsource") or {}).get("category") or "")
    except (yaml.YAMLError, AttributeError):
        return ""


def _logsource(yaml_text: str) -> tuple[str | None, str]:
    """(Windows event-log service or None, 'category/product/service' label, as the sample scores name it)."""
    import yaml
    try:
        ls = (yaml.safe_load(yaml_text) or {}).get("logsource") or {}
    except (yaml.YAMLError, AttributeError):
        return None, "these"
    product = str(ls.get("product") or "")
    service = str(ls.get("service") or "") if product == "windows" else None
    parts = (ls.get("category"), ls.get("product"), ls.get("service"))
    return service or None, "/".join(str(x) for x in parts if x) or "these"


def negated_placeholders(yaml_text: str) -> list[str]:
    """Placeholders under a NOT (a filter such as "not from your DC addresses"). Widened to any value, the filter
    excludes every event, so the rule can never fire: such a rule needs the value, not a wildcard."""
    from sigma.collection import SigmaCollection
    from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionNOT, ConditionValueExpression
    from sigma.types import Placeholder
    out: list[str] = []

    def walk(node, neg):
        neg = neg ^ isinstance(node, ConditionNOT)
        for a in getattr(node, "args", None) or ():
            walk(a, neg)
        if neg and isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
            out.extend(p.name for p in getattr(node.value, "s", ()) if isinstance(p, Placeholder))
    try:
        for c in SigmaCollection.from_yaml(yaml_text).rules[0].detection.parsed_condition:
            walk(c.parse(), False)
    except Exception:  # conversion reports a rule that does not parse
        return []
    return list(dict.fromkeys(out))


def stand_in(yaml_text: str, fill: dict | None) -> tuple[dict, str | None]:
    """A placeholder in a filter that the config leaves unset gets a stand-in value (`SET_<name>`) that no event
    holds: the filter then excludes nothing, so the query runs and also returns the events the filter was meant to
    drop (live run 4 Nov 2026: three DC machine-account rules had no query at all). Returns the fill and a note."""
    fill = dict(fill or {})
    need = [h for h in negated_placeholders(yaml_text) if h not in fill]
    if not need:
        return fill, None
    for h in need:
        fill[h] = [f"SET_{h}"]
    names = ", ".join(f"%{h}%" for h in need)
    return fill, (f"{names} {'is' if len(need) == 1 else 'are'} not set, so the filter uses the stand-in "
                  f"{', '.join('SET_' + h for h in need)} and excludes nothing: expect the events it was meant to "
                  "drop too. Set it under placeholders: in the config to cut them.")


def _placeholders(yaml_text: str) -> list[str]:
    """Placeholder names in the rule's detection (`|expand` values), as pySigma parses them. A %…% that is only
    text (`%comspec%` in a match value, `%20` in a reference URL) is not one."""
    from sigma.collection import SigmaCollection
    from sigma.types import Placeholder

    def values(item):
        for x in getattr(item, "detection_items", None) or ():
            yield from values(x) if hasattr(x, "detection_items") else x.value
    try:
        rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    except Exception:  # the conversion itself reports a rule that does not parse
        return []
    names = (part.name for det in rule.detection.detections.values() for v in values(det)
             for part in getattr(v, "s", ()) if isinstance(part, Placeholder))
    return list(dict.fromkeys(names))


_FIELD = re.compile(r"Invalid SigmaDetectionItem field name encountered: (\w+)")


def _holes_note(holes: list[str], fill: dict) -> str | None:
    set_, open_ = [h for h in holes if h in fill], [h for h in holes if h not in fill]
    names = lambda hs: ", ".join(f"%{h}%" for h in hs)  # noqa: E731
    parts = []
    if set_:
        parts.append(f"Placeholder{'s' if len(set_) > 1 else ''} {names(set_)} {'are' if len(set_) > 1 else 'is'} "
                     "set from your config.")
    if open_:
        many = len(open_) > 1
        parts.append(f"Placeholder{'s' if many else ''} {names(open_)} match{'' if many else 'es'} any value. Set "
                     f"{'them' if many else 'it'} under placeholders: in the config to narrow the query.")
    return " ".join(parts) or None


def convert_rule(yaml_text: str, targets: tuple[str, ...], placeholders: dict | None = None) -> dict[str, ConvResult]:
    from sigma.collection import SigmaCollection
    fill = dict(placeholders or {})
    holes = _placeholders(yaml_text)
    fill = {k: v for k, v in fill.items() if k in holes}
    fill, noisy = stand_in(yaml_text, fill) if holes else (fill, None)
    widened = _holes_note([h for h in holes if not str((fill.get(h) or [""])[0]).startswith("SET_")], fill) \
        if holes else None
    service, label = _logsource(yaml_text)
    antivirus = _category(yaml_text) == "antivirus"
    connector = "Microsoft Defender XDR connector"
    out: dict[str, ConvResult] = {}
    for t in targets:
        notes = [n for n in (widened, noisy) if n]
        try:
            if antivirus and t in ("defender", "sentinel"):
                queries = _antivirus(fill).convert(SigmaCollection.from_yaml(yaml_text))
                if t == "sentinel":
                    notes.append(f"Uses Defender XDR's DeviceEvents table (antivirus detections), which Sentinel "
                                 f"holds when the {connector} streams it.")
                q = _kql_keywords("\n".join(str(x) for x in queries))
                out[t] = ConvResult(True, q, None, " ".join(notes) or None)
                continue
            try:
                queries = TARGETS[t](fill).convert(SigmaCollection.from_yaml(yaml_text))
            except Exception as exc:
                table = _EVENT_TABLES.get(service or "")
                # an ASIM table without the field (logons have no TargetUserName): SecurityEvent keeps the event's
                # own field names, so Sentinel falls back to it as it does for a missing table
                field_gap = bool(_FIELD.search(str(exc))) and t == "sentinel" and bool(table)
                if "table name" not in str(exc) and not field_gap:
                    raise
                if t == "sentinel" and table:
                    try:
                        queries = _sentinel_events(table, fill).convert(SigmaCollection.from_yaml(yaml_text))
                    except Exception as again:
                        m = _FIELD.search(str(again))
                        if not m:
                            raise
                        out[t] = ConvResult(False, None, f"unsupported: Sentinel has no field for {m.group(1)}, "
                                                         f"in ASIM or in the {table} table")
                        continue
                    notes.append(f"Uses the {table} table (Windows {service} events), not ASIM.")
                elif t == "sentinel" and not service and "table name" in str(exc):
                    try:
                        queries = _defender(fill).convert(SigmaCollection.from_yaml(yaml_text))
                    except Exception:
                        out[t] = ConvResult(False, None, f"unsupported: {NAME[t]} has no table for {label} logs")
                        continue
                    xdr = str(queries[0]).split("\n", 1)[0].strip()
                    notes.append(f"ASIM has no table for {label} logs, so this uses Defender XDR's {xdr} table, "
                                 f"which Sentinel holds when the {connector} streams it.")
                elif t == "defender" and service:
                    out[t] = ConvResult(False, None, f"unsupported: Defender XDR has no table for the Windows "
                                                     f"{service} event log")
                    continue
                else:
                    out[t] = ConvResult(False, None, f"unsupported: {NAME.get(t, t)} has no table for {label} logs")
                    continue
            q = "\n".join(str(x) for x in queries)
            if t != "splunk":
                q = _kql_keywords(q)
            out[t] = (ConvResult(True, q, None, " ".join(notes) or None) if q.strip()
                      else ConvResult(False, None, "unsupported: empty query"))
        except Exception as exc:
            first = (str(exc).strip().splitlines() or [type(exc).__name__])[0]
            m = _FIELD.search(first)
            out[t] = ConvResult(False, None, f"unsupported: {NAME.get(t, t)} has no field for {m.group(1)}" if m
                                else "unsupported: " + first)
    return out
