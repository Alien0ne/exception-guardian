"""Live run, 4 Nov 2026: SigmaHQ had two rules for CVE-2021-1675, so guard asked for no draft, yet one missed its
attack sample and neither converted to Sentinel or Defender. A rule existing is not coverage: guard now lists
each such CVE under coverage_gaps and asks for one draft that closes the gap, once."""

from exception_guardian.cli import main
from exception_guardian.config import load_config
from exception_guardian.guard import run as guard_run
from exception_guardian.guard.run import run_guard

CVE = "CVE-2025-31161"  # R-CRUSH-003: covered only by a SigmaHQ rule in the demo
GOLD = "samples/golden/drafts/CVE-2025-54068.yml"


def _run(tmp_path):
    run = tmp_path / "demo"
    assert main(["demo", "--out", str(run)]) == 0
    return run


def _guard(run, monkeypatch, sentinel_ok=True, hits=None):
    real_convert, real_score = guard_run.convert_rule, guard_run.score_rule

    def convert(text, targets, *a):
        out = real_convert(text, targets, *a)
        if not sentinel_ok and "crushftp" in text.lower() and "sentinel" in out:
            ok = out["sentinel"]
            out["sentinel"] = type(ok)(**{**ok.__dict__, "ok": False, "query": "", "error": "no field for X"})
        return out

    def score(text, *a, **kw):
        res = real_score(text, *a, **kw)
        if hits is not None and "crushftp" in text.lower() and res.get("tested"):
            res = {**res, "attack_hits": hits}
        return res

    monkeypatch.setattr(guard_run, "convert_rule", convert)
    monkeypatch.setattr(guard_run, "score_rule", score)
    return run_guard(run, run / "drafts", load_config("guardian.yaml"))["R-CRUSH-003"]


def test_full_coverage_is_no_gap(tmp_path, monkeypatch):
    assert _guard(_run(tmp_path), monkeypatch)["coverage_gaps"] == []


def test_a_target_with_no_query_is_a_gap(tmp_path, monkeypatch):
    gaps = _guard(_run(tmp_path), monkeypatch, sentinel_ok=False)["coverage_gaps"]
    assert gaps == [{"cve": CVE, "no_query": ["sentinel"], "caught": True,
                     "reason": "no query for Microsoft Sentinel"}]


def test_a_rule_that_misses_its_attack_samples_is_a_gap(tmp_path, monkeypatch):
    gaps = _guard(_run(tmp_path), monkeypatch, hits=0)["coverage_gaps"]
    assert gaps[0]["cve"] == CVE and gaps[0]["caught"] is False
    assert "no rule catches its attack samples" in gaps[0]["reason"]


def test_the_handoff_asks_for_one_draft_and_a_draft_ends_the_ask(tmp_path, monkeypatch):
    run = _run(tmp_path)
    _guard(run, monkeypatch, sentinel_ok=False)
    handoff = (run / "handoff-guard.md").read_text()
    assert f"Close the gaps SigmaHQ leaves: {CVE}" in handoff
    text = open(GOLD).read().replace("CVE-2025-54068", CVE).replace("cve.2025-54068", "cve.2025-31161")
    (run / "drafts" / f"{CVE}.yml").write_text(text)
    entry = _guard(run, monkeypatch, sentinel_ok=False)
    assert entry["coverage_gaps"] == []  # asked once: a valid draft for the CVE ends it, even if it has gaps too


def test_the_report_names_the_gap(tmp_path, monkeypatch):
    run = _run(tmp_path)
    _guard(run, monkeypatch, sentinel_ok=False)
    assert main(["html", "--run", str(run)]) == 0
    page = (run / "report.html").read_text()
    assert f"<code>{CVE}</code>" in page and "no query for Microsoft Sentinel" in page


def test_each_hunt_card_says_what_its_rules_cover_together(tmp_path):
    """One rule saying "no query for Sentinel" read as a gap when another rule on the card had one."""
    import re
    run = _run(tmp_path)
    page = (run / "report.html").read_text()
    lines = re.findall(r'<p class="together">(.*?)</p>', page)
    assert lines and all("Together" in x for x in lines)
    assert any(re.search(r"Splunk \(\d+ rules?\), Microsoft Sentinel \(\d+\), Defender XDR \(\d+\)", x) for x in lines)
