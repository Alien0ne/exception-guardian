"""Deterministic grading. Every trigger carries its then/now evidence and source; text is never interpreted
except for the internal-keyword check on the justification."""
from __future__ import annotations

import re
from datetime import date

from .assets import ALL_ASSETS, covers, match
from .attack_paths import touching
from .config import Config
from .models import Asset, CveIntel, Grade, GradedException, RiskException, RuleType, Trigger

_SEVERITY = {"info": 0, "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_EXCLUSION_CODES = {"INTERNET_FACING", "PUBLIC_IP", "ATTACK_PATH", "NO_EXPIRY", "TOO_OLD", "NO_JUSTIFICATION",
                    "BLANKET"}
# a reason that says nothing: placeholders people type to get past a required field
_PLACEHOLDER = {"n/a", "na", "none", "tbd", "todo", "test", "testing", "temp", "x", "xx", "xxx", "asdf", "null", "nil"}


def no_reason(text: str) -> bool:
    t = " ".join(str(text or "").split()).lower().strip(" .-_*")
    return not any(c.isalnum() for c in t) or t in _PLACEHOLDER


def epss_source(i: CveIntel) -> str:
    """Where an EPSS trigger's numbers came from, naming a snapshot value at acceptance."""
    if i.epss_then_source and i.epss_then_source != i.source:
        return f"FIRST EPSS ({i.source}, value at acceptance from {i.epss_then_source})"
    return f"FIRST EPSS ({i.source})"


def fmt_score(x: float | None) -> str:
    if x is None:
        return "unknown"
    return ("%.5f" % x).rstrip("0").rstrip(".") or "0"


def _severity_change(exc: RiskException) -> int | None:
    """New minus original severity rank, or None when either is unknown."""
    o = _SEVERITY.get((exc.original_severity or "").lower())
    n = _SEVERITY.get((exc.new_severity or "").lower())
    return None if o is None or n is None else n - o


_NEGATION = re.compile(r"\b(not|non|never|no longer)[\s-]+$")


def _claims(just: str, keywords) -> bool:
    """The justification says a keyword ('internal'), not 'not internal' or 'non-internal'."""
    for k in keywords:
        for m in re.finditer(re.escape(k), just):
            if not _NEGATION.search(just[max(0, m.start() - 12):m.start()]):
                return True
    return False


MAX_LISTED = 3  # past this many assets, ATTACK_PATH and the "checked" notes are summarised


def _tag(i: CveIntel, many: bool, score: float | None) -> str:
    return f"{i.cve}: {fmt_score(score)}" if many else fmt_score(score)


def _few(items, n: int = MAX_LISTED) -> str:
    """'a, b, c and 17 more': long lists of IPs or names stay one readable line."""
    items = list(items)
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def _paths(a: Asset) -> str:
    n = a.attack_paths
    return f"{n} attack path{'s' if n != 1 else ''}" + (f" ({a.critical_paths} critical)" if a.critical_paths else "")


def grade(exc: RiskException, assets: list[Asset], intel: dict[tuple[str, date], CveIntel],
          cfg: Config, today: date, paths=(), sc_hosts: bool = False) -> GradedException:
    """`sc_hosts`: `assets` are Security Center hosts (for a tenable-sc rule), filtered to the rule's repository."""
    notes: list[str] = []
    if sc_hosts:
        repo = str(((exc.raw or {}).get("repository") or {}).get("id") or "")
        pool = [a for a in assets if not repo or f"repository:{repo}" in a.tags]
        matched = tuple(match(exc.targets, pool))
    elif covers(cfg.assets, exc.source):
        matched = tuple(match(exc.targets, assets))
    else:
        matched = ()
        notes.append(f"assets not checked: the configured asset list does not cover {exc.source} rules "
                     "(assets: for_sources sets which sources it covers)")
    cve_intel = tuple(intel[(c, exc.created)] for c in exc.cves if (c, exc.created) in intel)
    if not matched and (sc_hosts or covers(cfg.assets, exc.source)):
        notes.append("ASSET_UNKNOWN")
    unmatched = sorted({t.lstrip("!")[1:].split("=")[0] for t in exc.targets if t.lstrip("!").startswith("?")})
    if unmatched:
        notes.append(f"scope not checked: the rule filters on {', '.join(unmatched)}, which assets are not matched on")
    if not exc.cves:
        name = str(((exc.raw or {}).get("plugin") or {}).get("name") or "")
        excluded = (exc.raw or {}).get("x_excluded_cves") or []
        notes.append(f"the rule covers every CVE except {', '.join(excluded)}, so there is no CVE list to look up"
                     if excluded else
                     "compliance check (an audit result, not a vulnerability), so there is no CVE to look up"
                     if "<compliance>true</compliance>" in name else "no CVE intel")

    def done(triggers=()):
        g = max((t.grade for t in triggers), key=lambda x: x.rank, default=Grade.OK)
        return GradedException(exc, g, tuple(triggers), matched, cve_intel, tuple(notes))

    if exc.status == "disabled":
        notes.append("rule disabled")
        return done()
    change = _severity_change(exc) if exc.rule_type is RuleType.RECAST else None
    if change is not None and change >= 0:
        notes.append("recast raises severity, so it hides nothing" if change > 0
                     else "recast keeps the same severity, so it hides nothing")
        return done()

    t: list[Trigger] = []
    many = len(exc.cves) > 1  # name the CVE in each KEV and EPSS row, or three "in KEV since" rows look the same
    for i in cve_intel:
        tag = f"{i.cve} " if many else ""
        src = f"CISA KEV ({i.source})"
        if i.in_kev:
            then = ("not in KEV" if i.kev_date_added and i.kev_date_added > exc.created
                    else "added to KEV the day the rule was accepted" if i.kev_date_added == exc.created
                    else "already in KEV when accepted")
            now = f"{tag}in KEV since {i.kev_date_added}" + (", ransomware use" if i.kev_ransomware else "")
            t.append(Trigger("KEV", Grade.REVOKE, then, now, src))
        esrc = epss_source(i)
        if i.epss_now is not None and i.epss_now >= cfg.revoke_epss:
            t.append(Trigger("EPSS_HIGH", Grade.REVOKE, _tag(i, many, i.epss_at_created), _tag(i, many, i.epss_now), esrc))
        if (i.epss_now is not None and i.epss_at_created is not None
                and i.epss_now - i.epss_at_created >= cfg.review_epss_delta):
            t.append(Trigger("EPSS_ROSE", Grade.REVIEW, _tag(i, many, i.epss_at_created), _tag(i, many, i.epss_now), esrc))

    facing = [a for a in matched if a.internet_facing]
    if facing:
        then = "internal" if all(a.exposure_since and a.exposure_since > exc.created for a in facing) else None
        by_reason: dict[str, list[str]] = {}
        for a in facing:
            # what marked it, in the company's own terms: its tag, range or host list
            by_reason.setdefault(a.exposure_reason or "asset inventory", []).append(a.name)
        t.append(Trigger("INTERNET_FACING", Grade.REVOKE, then, "internet-facing",
                         " and ".join(f"{why}: {', '.join(names)}" for why, names in by_reason.items())))
    public = [a for a in matched if (a.public_ips or a.tenable_public or a.public_dns) and not a.internet_facing]
    if public and not facing:
        ips = _few(dict.fromkeys(ip for a in public for ip in a.public_ips))
        said = [x for x in ((f"has a public IP ({ips})" if ips else ""),
                            ("Tenable marks it public" if any(a.tenable_public for a in public) else ""),
                            ("public DNS name " + _few(dict.fromkeys(n for a in public for n in a.public_dns))
                             if any(a.public_dns for a in public) else "")) if x]
        hint = ", ".join(said[:-1]) + (" and " if len(said) > 1 else "") + said[-1]
        t.append(Trigger("PUBLIC_IP", Grade.REVIEW, None, f"{hint}, but it is not marked internet-facing",
                         "asset inventory: " + _few(a.name for a in public)))
    hits: list[tuple[Asset, Trigger]] = []
    checked: list[tuple[Asset, str]] = []
    for a in matched:
        if a.on_attack_path or a.critical:
            parts = []
            if a.on_attack_path:
                parts.append(f"on {_paths(a)}" if a.attack_paths else "on attack path")
            if a.critical:
                parts.append(f"ACR {a.acr:g} of 10" if a.acr is not None else "critical asset")
            now = ", ".join(parts) if a.acr is not None or a.attack_paths else parts[0]
            hits.append((a, Trigger("ATTACK_PATH", Grade.REVOKE, None, now,
                                    f"{a.context_source or 'asset inventory'}: {a.name}")))
        elif a.context_source:
            scores = [f"ACR {a.acr:g} of 10" if a.acr is not None else "", f"AES {a.aes:g} of 1000" if a.aes is not None
                      else "", ("not itself on an attack path" if a.attack_paths == 0 else "") if a.attack_paths is not None else ""]
            scores = [s for s in scores if s]
            checked.append((a, f"{a.name}: {', '.join(scores) or 'no ACR, AES or attack paths'} ({a.context_source})"))
    if len(hits) <= MAX_LISTED:
        t += [x for _, x in hits]
    else:  # a rule on many assets: one trigger naming the worst, not one line per asset
        srcs = {a.context_source or "asset inventory" for a, _ in hits}
        worst = sorted((a for a, _ in hits if a.attack_paths), key=lambda a: (-a.attack_paths, a.name))[:MAX_LISTED]
        named = ", ".join(f"{a.name} ({a.attack_paths}" + (f", {a.critical_paths} critical" if a.critical_paths else "")
                          + ")" for a in worst)
        now = f"{len(hits)} covered assets are on attack paths or critical. " + (
            f"Most paths: {named}" if named else f"For example {', '.join(a.name for a, _ in hits[:MAX_LISTED])}")
        t.append(Trigger("ATTACK_PATH", Grade.REVOKE, None, now,
                         f"{srcs.pop() if len(srcs) == 1 else 'asset inventory'}: {len(hits)} assets"))
    if len(checked) <= MAX_LISTED:
        notes += [n for _, n in checked]
    else:
        srcs = {a.context_source for a, _ in checked}
        notes.append(f"{len(checked)} more covered assets: not themselves on attack paths, ACR below {cfg.critical_acr:g} "
                     f"({srcs.pop() if len(srcs) == 1 else 'Tenable One inventory'})")
    path_internet = False
    if paths and exc.cves:
        linked, elsewhere = touching(exc.cves, list(matched), list(paths))
        for p, cves, how in linked[:MAX_LISTED]:
            t.append(Trigger("ATTACK_PATH_CVE", Grade.REVOKE, None,
                             f"{', '.join(cves)} is used in an attack path: {p.line()}, and {' and '.join(how[:MAX_LISTED])}",
                             f"Tenable One attack paths: {p.name}"))
            path_internet = path_internet or p.from_internet
        if len(linked) > MAX_LISTED:
            notes.append(f"{len(linked) - MAX_LISTED} more attack paths use this rule's CVEs on its assets")
        if elsewhere and not linked:
            p, cves, _ = elsewhere[0]
            n = len(elsewhere)
            t.append(Trigger("PATH_CVE_ELSEWHERE", Grade.REVIEW, None,
                             f"{', '.join(cves)} is used in {n} attack path{'s' if n != 1 else ''} elsewhere, "
                             f"e.g. {p.line()}", f"Tenable One attack paths: {p.name}"))
    if exc.expires is None:
        t.append(Trigger("NO_EXPIRY", Grade.REVIEW, None, "no expiry", "rule metadata"))
    if no_reason(exc.justification):
        t.append(Trigger("NO_JUSTIFICATION", Grade.REVIEW, None, "no reason given", "rule metadata"))
    if ALL_ASSETS in exc.targets:
        checked_assets = sc_hosts or covers(cfg.assets, exc.source)
        t.append(Trigger("BLANKET", Grade.REVIEW, None,
                         f"every asset ({len(matched)} today)" if checked_assets else "every asset", "rule metadata"))
    age = (today - exc.created).days
    if age > cfg.review_max_age_days:
        t.append(Trigger("TOO_OLD", Grade.REVIEW, str(exc.created), f"{age} days old", "rule metadata"))
    if exc.expires and exc.expires < today and exc.status == "enabled":
        t.append(Trigger("EXPIRED_STILL_ENABLED", Grade.REVIEW, None, f"expired {exc.expires}, still enabled",
                         "rule metadata"))
    just = exc.justification.lower()
    if (facing or public or path_internet) and _claims(just, cfg.internal_keywords):
        now = ("says internal, but the asset is internet-facing" if facing
               else "says internal, but the asset has a public IP" if public
               else "says internal, but an attack path from the internet uses this CVE")
        t.append(Trigger("JUSTIFICATION_CONTRADICTED", Grade.REVIEW, "says internal", now,
                         "justification vs " + ("asset inventory" if facing or public else "Tenable One attack paths")))

    if exc.rule_type is RuleType.EXCLUSION:
        t = [x for x in t if x.code in _EXCLUSION_CODES]
    return done(t)
