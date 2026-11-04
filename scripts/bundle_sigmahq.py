#!/usr/bin/env python3
"""Bundle every SigmaHQ rule the CVE index points at, unchanged, and rewrite the credits notice.

    python scripts/build_sigmahq_index.py <sigma_clone_dir> src/exception_guardian/data/sigmahq_index.json
    python scripts/bundle_sigmahq.py <sigma_clone_dir>

The clone must be at the index's pinned commit. Files are copied byte for byte into
src/exception_guardian/data/sigmahq/ (DRL 1.1: authors stay in each file; NOTICE.md lists title, author and
commit-pinned source for every file). The two generic web-shell rules are kept as well."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "src" / "exception_guardian" / "data"
BUNDLE = DATA / "sigmahq"
GENERIC = ("rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml",
           "rules/windows/process_creation/proc_creation_win_webshell_susp_process_spawned_from_webserver.yml")


def main(clone: str) -> None:
    src = Path(clone)
    index = json.loads((DATA / "sigmahq_index.json").read_text())
    sha = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True,
                         check=True).stdout.strip()
    if sha != index["commit"]:
        raise SystemExit(f"clone is at {sha}, the index is pinned to {index['commit']}")
    paths = sorted({e["path"] for v in index["cves"].values() for e in v} | set(GENERIC))
    names = [Path(p).name for p in paths]
    if len(set(names)) != len(names):
        raise SystemExit("two rules share a file name; the bundle is flat")
    rows = []
    for p in paths:
        shutil.copyfile(src / p, BUNDLE / Path(p).name)
        doc = yaml.safe_load((src / p).read_text())
        cell = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
        rows.append(f"| `{Path(p).name}` | {cell(doc.get('title', ''))} | {cell(doc.get('author', ''))} | "
                    f"https://github.com/SigmaHQ/sigma/blob/{sha}/{p} |")
    (BUNDLE / "NOTICE.md").write_text(
        "# Bundled SigmaHQ rules\n\n"
        f"These {len(paths)} files are copied unchanged from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) at commit "
        f"`{sha}` and are licensed under the [Detection Rule License (DRL) 1.1]"
        "(https://github.com/SigmaHQ/Detection-Rule-License). Authors are kept in each file's `author` field. "
        "Regenerate from a SigmaHQ clone: `scripts/build_sigmahq_index.py` (the CVE index), then `scripts/bundle_sigmahq.py`.\n\n"
        "| File | Title | Author | Source |\n|---|---|---|---|\n" + "\n".join(rows) + "\n")
    print(f"bundled {len(paths)} rules at {sha}")


if __name__ == "__main__":
    main(sys.argv[1])
