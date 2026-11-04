"""Bundled SigmaHQ CVE index (DRL 1.1 rules keep their author and source link)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

DATA = Path(__file__).resolve().parent.parent / "data"
BUNDLE = DATA / "sigmahq"
_GENERIC = {"linux": "rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml",
            "windows": "rules/windows/process_creation/proc_creation_win_webshell_susp_process_spawned_from_webserver.yml"}


@dataclass(frozen=True)
class SigmaRef:
    title: str
    author: str
    url: str
    bundled_path: Path | None


@lru_cache(maxsize=1)
def _index() -> dict:
    return json.loads((DATA / "sigmahq_index.json").read_text())


def _ref(entry: dict) -> SigmaRef:
    local = BUNDLE / Path(entry["path"]).name
    return SigmaRef(entry["title"], entry["author"], entry["url"], local if local.exists() else None)


def rules_for_cve(cve: str) -> list[SigmaRef]:
    refs = [_ref(e) for e in _index()["cves"].get(cve.upper(), [])]
    return sorted(refs, key=lambda r: r.bundled_path is None)  # bundled (shippable) rules first


def generic_rules(os: str | None) -> list[SigmaRef]:
    """Generic web-shell behaviour rule for the host's OS family (bundled)."""
    key = (os or "").lower()
    family = "windows" if "windows" in key else "linux" if "linux" in key else None
    if family is None:
        return []
    src_path = _GENERIC[family]
    path = BUNDLE / Path(src_path).name
    doc = yaml.safe_load(path.read_text())
    url = f"https://github.com/SigmaHQ/sigma/blob/{_index()['commit']}/{src_path}"
    return [SigmaRef(doc["title"], str(doc["author"]), url, path)]
