"""Run Sigma rules against labelled sample logs, so a rule ships with evidence that it fires (and how often
it fires on benign activity), not only proof that it parses.

Events are JSON objects in Sigma field names, one per line in samples/logs/*.jsonl, with three bookkeeping keys:
`_logsource` ("<category>/<product>" or "<category>"), `_label` ("attack" or "benign") and, on attack events,
`_attack` (the CVEs the event exploits). `_note` explains the event. Conditions are evaluated on the tree pySigma
parses; any construct this evaluator does not know marks the rule untested rather than guessing."""
from __future__ import annotations

import ipaddress
import json
import re
from contextvars import ContextVar
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import (ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR,
                              ConditionValueExpression)
from sigma.types import (Placeholder, SigmaCasedString, SigmaCIDRExpression, SigmaNull, SigmaNumber,
                         SigmaRegularExpression, SigmaRegularExpressionFlag, SigmaString, SpecialChars)

_RE_FLAGS = {SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE, SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
             SigmaRegularExpressionFlag.DOTALL: re.DOTALL}


_FILL: ContextVar[dict] = ContextVar("placeholders", default={})


class Unsupported(Exception):
    pass


def load_events(logs_dir: Path) -> list[dict]:
    events: list[dict] = []
    for p in sorted(Path(logs_dir).glob("*.jsonl")):
        for line in p.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def _pattern(s: SigmaString) -> re.Pattern:
    parts = []
    for part in s.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, str):
            parts.append(re.escape(part))
        elif isinstance(part, Placeholder):  # the config's values, else any value, as in the queries (convert.py)
            vals = _FILL.get().get(part.name)
            parts.append("(?:" + "|".join(re.escape(v).replace(r"\*", ".*").replace(r"\?", ".") for v in vals) + ")"
                         if vals else ".*")
        else:
            raise Unsupported(f"special character {part}")
    flags = re.DOTALL if isinstance(s, SigmaCasedString) else re.IGNORECASE | re.DOTALL  # |cased keeps case
    return re.compile("".join(parts), flags)


_QUANT = re.compile(r"[*+]|\{\d*,?\d*\}")


def nested_quantifier(src: str) -> bool:
    """A repeated group that repeats something inside it, like (a+)+: the shape that backtracks for seconds on a
    short line (ReDoS). Python's re has no timeout, so such a pattern is refused before it runs."""
    stack, i, in_class = [False], 0, False
    while i < len(src):
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
            if src[i + 1:i + 2] == "]":
                i += 1
        elif c == "(":
            stack.append(False)
        elif c == ")" and len(stack) > 1:
            inner = stack.pop()
            q = _QUANT.match(src, i + 1)
            if q and inner and q.group() not in ("{1}", "{0,1}"):
                return True
            stack[-1] = stack[-1] or inner or bool(q)
            if q:
                i = q.end()
                continue
        else:
            q = _QUANT.match(src, i)
            if q:
                stack[-1] = True
                i = q.end()
                continue
        i += 1
    return False


def _value_matches(value, actual, keyword: bool = False) -> bool:
    if isinstance(value, SigmaNull):
        return actual is None
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(_value_matches(value, a, keyword) for a in actual)
    if isinstance(value, SigmaString):
        pat = _pattern(value)  # a keyword is a full-text search term: it may sit anywhere in a field
        return (pat.search(str(actual)) if keyword else pat.fullmatch(str(actual))) is not None
    if isinstance(value, SigmaNumber):
        try:
            return float(actual) == float(value.number)
        except (TypeError, ValueError):
            return False
    if isinstance(value, SigmaRegularExpression):
        src = value.regexp.to_plain() if hasattr(value.regexp, "to_plain") else str(value.regexp)
        if nested_quantifier(src):
            raise Unsupported("regular expression with a nested quantifier (like (a+)+), which can hang a SIEM "
                              "on one long line. Rewrite it without a repeated group that repeats inside")
        flags = 0
        for f in value.flags or ():
            flags |= _RE_FLAGS.get(f, 0)
        try:
            return re.search(src, str(actual), flags) is not None
        except re.error as exc:
            raise Unsupported(f"regular expression {exc}") from exc
    if isinstance(value, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in value.network
        except ValueError:
            return False
    raise Unsupported(type(value).__name__)


def _eval(node, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _value_matches(node.value, event.get(node.field))
    if isinstance(node, ConditionValueExpression):  # keyword: anywhere in the event's own fields
        return any(_value_matches(node.value, v, keyword=True) for k, v in event.items() if not k.startswith("_"))
    raise Unsupported(type(node).__name__)


def _logsource(rule) -> tuple[str | None, str | None]:
    return rule.logsource.category, rule.logsource.product


def _same_source(rule_ls: tuple[str | None, str | None], event: dict) -> bool:
    cat, _, prod = str(event.get("_logsource", "")).partition("/")
    return cat == rule_ls[0] and (rule_ls[1] is None or prod == rule_ls[1])


def _rule(yaml_text: str):
    return SigmaCollection.from_yaml(yaml_text).rules[0]


def rule_matches(yaml_text: str, event: dict) -> bool:
    rule = _rule(yaml_text)
    return any(_eval(c.parse(), event) for c in rule.detection.parsed_condition)


# Known typos in pinned SigmaHQ tags: the WinRAR rules for CVE-2023-38831 are tagged cve.2023-38331 (their file
# names and references say 38831). Read as the real CVE, so its samples count.
TAG_TYPOS = {"CVE-2023-38331": "CVE-2023-38831"}


def _stage_ids(yaml_text: str) -> set[str]:
    """The Windows event IDs a rule's selections ask for (filters left out). One CVE can be logged at several stages
    (a computer account created as 4741, then directory replication as 4662), each with its own rule; an attack
    sample of another event ID is another stage, not a miss (live run, 4 Nov 2026). Empty: the rule names none."""
    import yaml
    try:
        det = (yaml.safe_load(yaml_text) or {}).get("detection") or {}
    except Exception:
        return set()
    found: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if str(k).split("|")[0] == "EventID":
                    found.update(str(x) for x in (v if isinstance(v, list) else [v]))
                else:
                    walk(v)
        elif isinstance(node, list):
            for x in node:
                walk(x)
    for name, body in det.items():
        if name != "condition" and not str(name).lower().startswith("filter"):
            walk(body)
    return found


def _rule_cves(rule) -> set[str]:
    return {TAG_TYPOS.get(c, c) for c in (f"CVE-{t.name}".upper() for t in rule.tags if t.namespace == "cve")}


def score_rule(yaml_text: str, events: list[dict], cves: tuple[str, ...], any_attack: bool = False,
               own_cves_only: bool = False, placeholders: dict | None = None) -> dict:
    token = _FILL.set(dict(placeholders or {}))
    try:
        return _score(yaml_text, events, cves, any_attack, own_cves_only)
    finally:
        _FILL.reset(token)


def _score(yaml_text: str, events: list[dict], cves: tuple[str, ...], any_attack: bool, own_cves_only: bool) -> dict:
    """Attack samples: events exploiting the rule's own CVE tags (or, for a rule without them, the exception's
    CVEs). A generic rule (any_attack) watches for behaviour after any exploit, so every attack event of its log
    source counts. Benign samples: every benign event from the rule's log source."""
    try:
        rule = _rule(yaml_text)
        conds = [c.parse() for c in rule.detection.parsed_condition]
    except Exception as exc:
        return {"tested": False, "reason": f"unsupported: {exc}"}
    from .convert import stand_in
    _FILL.set(stand_in(yaml_text, _FILL.get())[0])  # an unset filter value excludes nothing, as in the queries
    ls = _logsource(rule)
    name = "/".join(x for x in (*ls, rule.logsource.service) if x) or "unknown"
    pool = [e for e in events if _same_source(ls, e) or str(e.get("_logsource", "")) == name]
    if not pool:
        return {"tested": False, "reason": f"no sample logs for {name}", "logsource": name}
    # a draft is scored on the CVE it is filed under (own_cves_only), never on whatever its tags claim
    wanted = {c.upper() for c in cves} if own_cves_only else (_rule_cves(rule) or {c.upper() for c in cves})
    attacks = [e for e in pool if e.get("_label") == "attack"
               and (any_attack or wanted & {c.upper() for c in e.get("_attack", [])})]
    stages = _stage_ids(yaml_text)
    other = [e for e in attacks if stages and "EventID" in e and str(e["EventID"]) not in stages]
    attacks = [e for e in attacks if e not in other]
    benign = [e for e in pool if e.get("_label") == "benign"]
    try:
        hit = lambda e: any(_eval(c, e) for c in conds)  # noqa: E731
        missed = [e for e in attacks if not hit(e)]
        attack_hits = len(attacks) - len(missed)
        benign_hit = [e for e in benign if hit(e)]
    except Unsupported as exc:
        return {"tested": False, "reason": f"unsupported: {exc}"}
    except Exception as exc:  # one rule the evaluator cannot handle must not stop guard for every other rule
        return {"tested": False, "reason": f"unsupported: {type(exc).__name__}: {exc}"}
    return {"tested": True, "attack_hits": attack_hits, "attack_total": len(attacks),
            "benign_hits": len(benign_hit), "benign_total": len(benign),
            "benign_hit_notes": [str(e.get("_note", "")) for e in benign_hit], "logsource": name,
            **({"attack_missed_notes": m} if (m := [str(e["_note"]) for e in missed if e.get("_note")][:3]) else {}),
            "agent_events": sum(1 for e in attacks + benign if e.get("_origin") == "agent"),
            **({"attack_scope": "any CVE"} if any_attack else {}),
            **({"other_stage": len(other)} if other else {})}
