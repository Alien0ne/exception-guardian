"""Tenable One context for the assets the exceptions cover: ACR, AES and attack paths. Only covered assets are
looked up, so a tenant with 150,000 assets costs two calls (context, then tags) per covered asset. A lookup failure
is a note: grading falls back to the asset list's own critical and attack-path flags."""
from __future__ import annotations

from dataclasses import replace

from .assets import match, tag_key
from .config import Config, ExposureConfig
from .models import Asset
from .parallel import parallel_map

MAX_LOOKUPS = Config.max_context_lookups  # one default, in config.py


def _num(v) -> float | None:
    """A score from Tenable One, or None: text, booleans and anything else are dropped, never shown."""
    if isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _count(v) -> int | None:
    n = _num(v)
    return int(n) if n is not None and n >= 0 and n == int(n) else None


def enrich_context(assets: list[Asset], exceptions, client, critical_acr: float,
                   max_lookups: int = MAX_LOOKUPS,
                   internet_tags: tuple[str, ...] = ExposureConfig.internet_tags) -> tuple[list[Asset], list[str]]:
    # disabled rules hide nothing, so their assets are not worth a lookup; rules naming assets go before rules on
    # every asset, so a capped run still looks up what a specific exception covers
    live = [e for e in exceptions if e.status != "disabled"]
    covered: list[str] = []
    for e in sorted(live, key=lambda e: "*" in e.targets):
        for a in match(e.targets, assets):
            if a.id not in covered:
                covered.append(a.id)
    notes: list[str] = []
    if len(covered) > max_lookups:
        notes.append(f"asset context: {len(covered)} covered assets, but only the first {max_lookups} were looked up. "
                     "Raise max_context_lookups in the config to look up more")
        covered = covered[:max_lookups]
    ctx: dict[str, dict] = {}
    tags: dict[str, list[str]] = {}
    read_tags = getattr(client, "asset_tags", None)
    failed, first, tag_failed, tag_first = 0, None, 0, None

    def look(aid: str):
        # each read on its own: one failed lookup must not cost the asset its other read, or other assets theirs.
        # The asset list may carry no tags (on some tenants): the single-asset record does
        def get(fn):
            try:
                return fn(aid)
            except Exception as exc:
                return exc
        return get(client.asset_context), (get(read_tags) if read_tags else None)

    for aid, (c, t) in zip(covered, parallel_map(look, covered, label="asset context")):
        if isinstance(c, Exception):
            failed += 1
            first = first or f"{type(c).__name__}: {c}"
        elif c:
            ctx[aid] = c
        if isinstance(t, Exception):
            tag_failed += 1
            tag_first = tag_first or f"{type(t).__name__}: {t}"
        elif t is not None:
            tags[aid] = t
    if failed and failed == len(covered):
        notes.append(f"source asset context failed: all {failed} lookups failed ({first}), so every asset uses the "
                     "asset list's flags only")
    elif failed:
        notes.append(f"asset context: {failed} of {len(covered)} lookups failed ({first}), so those assets use the "
                     "asset list's flags only")
    if tag_failed:
        notes.append(f"asset tags: {tag_failed} of {len(covered)} tag reads failed ({tag_first}), so those assets "
                     "use the asset list's tags only")
    facing = {tag_key(t) for t in internet_tags}
    out = []
    for a in assets:
        extra = [t for t in tags.get(a.id, []) if t not in a.tags]
        if extra:
            a = replace(a, tags=a.tags + tuple(extra))
            hit = next((t for t in extra if tag_key(t) in facing), None)
            if hit and not a.internet_facing:
                k, _, v = hit.partition(":")
                a = replace(a, internet_facing=True, exposure_reason=f"tag {k.strip()}:{v.strip()}")
        c = ctx.get(a.id)
        if not c:
            out.append(a)
            continue
        acr, paths = _num(c.get("acr")), _count(c.get("paths"))
        out.append(replace(
            a, acr=acr, aes=_num(c.get("aes")), attack_paths=paths, critical_paths=_count(c.get("critical_paths")),
            context_source=c["source"],
            critical=(acr >= critical_acr) if acr is not None else a.critical,
            on_attack_path=(paths > 0) if paths is not None else a.on_attack_path))
    return out, notes
