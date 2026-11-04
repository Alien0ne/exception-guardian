"""CVE ids come from untrusted sources: split, normalise and validate them before anything uses them."""
from __future__ import annotations

import re
from typing import Iterable

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_FIND = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_SPLIT = re.compile(r"[,;\s]+")


def is_cve(s: str) -> bool:
    return bool(CVE_RE.match(s))


def split_cves(values: Iterable[str] | str) -> tuple[tuple[str, ...], list[str]]:
    """Return (valid upper-cased CVE ids, de-duplicated in order; rejected tokens)."""
    if isinstance(values, str):
        values = [values]
    good: list[str] = []
    bad: list[str] = []
    for v in values:
        for tok in _SPLIT.split(str(v or "").strip()):
            if not tok:
                continue
            up = tok.upper()
            if is_cve(up):
                if up not in good:
                    good.append(up)
            else:
                bad.append(tok)
    return tuple(good), bad


def find_cves(text: str) -> tuple[str, ...]:
    """All CVE ids mentioned anywhere in free text (plugin attributes, xrefs)."""
    out: list[str] = []
    for m in _FIND.findall(text or ""):
        if m.upper() not in out:
            out.append(m.upper())
    return tuple(out)
