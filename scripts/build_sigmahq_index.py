#!/usr/bin/env python3
"""Build the SigmaHQ CVE index: python scripts/build_sigmahq_index.py <sigma_clone_dir> <out_json>.

Walks rules* folders (skipping deprecated, regression_data, unsupported), collects CVE ids from file paths,
`tags` (cve.YYYY-NNNN) and `references`, and records title, author, path and a commit-pinned GitHub URL."""
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SKIP = {"deprecated", "regression_data", "unsupported"}


def main(clone: str, out: str) -> None:
    root = Path(clone)
    sha = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    index: dict[str, list[dict]] = {}
    for top in sorted(p for p in root.iterdir() if p.is_dir() and p.name.startswith("rules")):
        for f in sorted(top.rglob("*.yml")):
            rel = f.relative_to(root).as_posix()
            if SKIP & set(rel.split("/")):
                continue
            try:
                doc = next(yaml.safe_load_all(f.read_text()))
            except Exception:
                continue
            if not isinstance(doc, dict):
                continue
            found = set(m.upper() for m in CVE.findall(rel))
            for t in doc.get("tags") or []:
                if str(t).lower().startswith("cve."):
                    found.add("CVE-" + str(t)[4:].upper())
            for r in doc.get("references") or []:
                found.update(m.upper() for m in CVE.findall(str(r)))
            entry = {"title": doc.get("title", ""), "author": str(doc.get("author", "")), "path": rel,
                     "url": f"https://github.com/SigmaHQ/sigma/blob/{sha}/{rel}"}
            for c in found:
                index.setdefault(c, []).append(entry)
    Path(out).write_text(json.dumps({"commit": sha, "cves": dict(sorted(index.items()))}, indent=1) + "\n")
    print(f"{len(index)} CVEs indexed at {sha}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
