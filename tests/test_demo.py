from exception_guardian.cli import main


def test_demo_end_to_end_offline(tmp_path, monkeypatch, capsys):
    def no_net(*a, **k): raise AssertionError("network call in demo")
    monkeypatch.setattr("socket.socket.connect", no_net)  # in-process run, so the patch applies
    assert main(["demo", "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "R-HERO-001" in out and "0.96284" in out and "CVE-2025-54068.splunk.txt" in out
    for f in ("report.md", "findings.json", "guard.json", "approval-plan.md", "rules/R-HERO-001/CVE-2025-54068.sentinel.txt"):
        assert (tmp_path / f).exists()
    assert not (tmp_path / "applied-changes.log").exists()  # demo never applies


def test_demo_shows_changes_since_last_run(tmp_path, capsys):
    assert main(["demo", "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Since the last run (2026-10-26)" in out and "EXCL-001: REVIEW → REVOKE" in out
    assert (tmp_path / "changes.md").exists() and (tmp_path / "previous" / "findings.json").exists()


def test_find_cli_previous_flag(tmp_path, capsys):
    prev = tmp_path / "prev"
    assert main(["find", "--config", "samples/history/2026-10-26/guardian.yaml", "--offline",
                 "--out", str(prev), "--today", "2026-10-26"]) == 0
    assert main(["find", "--offline", "--out", str(tmp_path / "cur"), "--today", "2026-11-02",
                 "--previous", str(prev)]) == 0
    out = capsys.readouterr().out
    assert "changes: " in out and "1 got worse" in out


def test_checked_in_example_matches_a_fresh_demo_run(tmp_path, capsys):
    """examples/demo-run is what the README sends readers to: regenerate it whenever the demo's output changes
    (exception-guardian demo --out examples/demo-run, then make its paths relative)."""
    from pathlib import Path
    assert main(["demo", "--out", str(tmp_path)]) == 0
    ex = Path("examples/demo-run")
    fresh = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert sorted(p.relative_to(ex).as_posix() for p in ex.rglob("*") if p.is_file()) == fresh
    for f in ("report.md", "approval-plan.md", "changes.md", "hunt-briefs/R-HERO-001.md",
              "rules/R-HERO-001/CVE-2025-54068.sentinel.txt"):
        assert (ex / f).read_text() == ((tmp_path / f).read_text().replace(f"{tmp_path}", "examples/demo-run")
                                    .replace(tmp_path.name, "examples/demo-run")), f
    assert "/home/" not in "".join(p.read_text() for p in ex.rglob("*") if p.is_file())


def test_worked_example_quotes_what_the_demo_prints(tmp_path, capsys):
    """references/worked-example.md is what Claude learns to say: its sources and scores must be the demo's own."""
    from pathlib import Path
    assert main(["demo", "--out", str(tmp_path)]) == 0
    page = Path("references/worked-example.md").read_text()
    report = (tmp_path / "report.md").read_text()
    brief = (tmp_path / "hunt-briefs" / "R-HERO-001.md").read_text()
    for row in [r for r in page.splitlines() if r.startswith("| ") and r.split("|")[1].strip().isupper()]:
        source = row.split("|")[4].strip()
        assert source in report, row
    for score in ("4 of 4", "1 of 11", "3 of 3", "0 of 6"):
        assert f"fires on {score}" in brief or f", {score} benign" in brief, score
    generic = next(r for r in page.splitlines() if "generic SigmaHQ" in r and r.startswith("|"))
    caught = generic.split("|")[3].strip()
    assert f"fires on {caught} attack samples" in brief, caught


def test_examples_readme_names_only_real_files_and_counts():
    """examples/README.md is the first thing a visitor reads in that folder: every path it names exists, and its
    grade counts are the checked-in run's own."""
    import json
    import re
    from collections import Counter
    from pathlib import Path
    page = Path("examples/README.md").read_text()
    for name in re.findall(r"`(demo-run/[^`]+)`", page):
        assert (Path("examples") / name).exists(), name
    f = json.loads(Path("examples/demo-run/findings.json").read_text())
    counts = Counter(x["grade"] for x in f["findings"])
    assert f"REVOKE {counts['REVOKE']}, REVIEW {counts['REVIEW']}, OK {counts['OK']}" in page
    assert f"{len(f['findings'])} exceptions" in page
