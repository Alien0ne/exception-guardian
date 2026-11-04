"""Every SigmaHQ rule the CVE index points at ships in the bundle, valid and credited, so live CVEs get queries;
the generic web-shell rule is a fallback for CVEs SigmaHQ has no rule for."""
import json
from dataclasses import replace
from datetime import date
from pathlib import Path

from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.guard.run import run_guard
from exception_guardian.guard.sigmahq import BUNDLE, DATA, rules_for_cve
from exception_guardian.guard.validate import validate_rule

INDEX = json.loads((DATA / "sigmahq_index.json").read_text())
GOLDEN = Path("samples/golden/drafts")


def test_every_indexed_rule_is_bundled_valid_and_credited():
    notice = (BUNDLE / "NOTICE.md").read_text()
    paths = {e["path"] for v in INDEX["cves"].values() for e in v}
    assert len(paths) > 250
    for p in paths:
        f = BUNDLE / Path(p).name
        assert f.is_file(), p
        assert f"`{f.name}`" in notice and f"{INDEX['commit']}/{p}" in notice, p
        assert validate_rule(f.read_text(), drafted=False) == [], p


def test_bundled_files_are_listed_in_the_notice_and_nothing_else_ships():
    notice = (BUNDLE / "NOTICE.md").read_text()
    for f in BUNDLE.glob("*.yml"):
        assert f"`{f.name}`" in notice, f.name


def test_lab_cves_resolve_to_bundled_rules():
    for cve in ("CVE-2021-34527", "CVE-2020-1472"):
        refs = rules_for_cve(cve)
        assert refs and all(r.bundled_path for r in refs), cve


def _demo(tmp_path, cves=None, rid="R-CRUSH-003"):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    if cves:
        p = tmp_path / "findings.json"
        d = json.loads(p.read_text())
        for f in d["findings"]:
            if f["exception"]["rule_id"] == rid:
                f["exception"]["cves"] = cves
        p.write_text(json.dumps(d))
    return run_guard(tmp_path, GOLDEN, load_config("guardian.yaml"))


def test_generic_rule_is_dropped_when_sigmahq_has_a_specific_rule(tmp_path):
    g = _demo(tmp_path)
    assert not any(r["origin"] == "generic" for r in g["R-CRUSH-003"]["rules"])
    assert any(r["origin"] == "generic" for r in g["R-HERO-001"]["rules"])  # drafts only: the fallback stays


def test_printnightmare_gets_converted_queries_and_no_generic_rule(tmp_path):
    g = _demo(tmp_path, cves=["CVE-2021-34527"])
    rules = g["R-CRUSH-003"]["rules"]
    assert rules and all(r["origin"] == "sigmahq" and r["file"] for r in rules)
    assert any(c["ok"] for r in rules for c in r["conversions"].values())
    assert g["R-CRUSH-003"]["missing_drafts"] == []


def _score(name, cves):
    from exception_guardian.guard.logtest import load_events, score_rule
    return score_rule((BUNDLE / name).read_text(), load_events(Path("samples/logs")), cves)


def test_windows_rules_are_tested_against_windows_sample_logs():
    for name, cves in (("proc_creation_win_crushftp_susp_child_processes.yml", ("CVE-2025-31161",)),
                       ("image_load_exploit_cve_2021_1675_spoolsv_dll_load.yml", ("CVE-2021-34527",)),
                       ("registry_event_cve_2021_1675_mimikatz_printernightmare_drivers.yml", ("CVE-2021-34527",)),
                       ("proc_creation_win_exploit_cve_2020_1472_zero_poc.yml", ("CVE-2020-1472",))):
        s = _score(name, cves)
        assert s["tested"] and s["attack_total"] >= 1 and s["benign_total"] >= 1, (name, s)
        assert s["attack_hits"] >= 1, (name, s)
