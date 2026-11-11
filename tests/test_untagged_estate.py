"""An estate where no asset carries a tag: can `find` still say which accepted risks sit on internet-facing hosts?
`samples/untagged` fixes the truth in advance (truth.json, which the tool never reads). The run is scored against
it at three points: `find` alone, after the exposure command has checked the claims itself, and after a person has
approved the drafted host list. The DNS and internet-scan answers are canned (evidence.json): no network."""
import csv
import json
from pathlib import Path

import pytest

from exception_guardian import exposure_claims
from exception_guardian.cli import main

S = Path("samples/untagged").resolve()
TRUTH = {h["name"]: h["internet_facing"] for h in json.loads((S / "truth.json").read_text())["hosts"]}
EXPOSED = {n for n, t in TRUTH.items() if t}
CONFIG = """sources:
  - name: tenable-vm
    fixture_dir: {s}
assets:
  fixture: {s}/assets.json
intel_snapshot_dir: {intel}
offline: true
{extra}"""


def _find(tmp_path, name, extra="", *args):
    cfg = tmp_path / f"{name}.yaml"
    cfg.write_text(CONFIG.format(s=S, intel=Path("samples/intel").resolve(), extra=extra))
    out = tmp_path / name
    assert main(["find", "--config", str(cfg), "--out", str(out), "--today", "2026-11-02", *args]) == 0
    return out, json.loads((out / "findings.json").read_text())


def _facing(d):
    return {a["name"] for f in d["findings"] for a in f["assets"] if a["internet_facing"]}


def _grades(d):
    return {f["assets"][0]["name"]: f["grade"] for f in d["findings"]}


def _codes(d, host):
    return {t["code"] for f in d["findings"] if f["assets"][0]["name"] == host for t in f["triggers"]}


@pytest.fixture
def stages(tmp_path, monkeypatch):
    ev = json.loads((S / "evidence.json").read_text())
    monkeypatch.setattr(exposure_claims, "resolve_dns", lambda name: ev["dns"].get(name, []))
    monkeypatch.setattr(exposure_claims, "shodan_lookup", lambda ip: ev["internet_scan"].get(ip))
    monkeypatch.setenv("SHODAN_API_KEY", "not-a-key")
    run0, d0 = _find(tmp_path, "find-only")
    assert main(["exposure", "--run", str(run0), "--claims", str(S / "claims.json")]) == 0
    _, d1 = _find(tmp_path, "checked", "", "--exposure-claims", str(run0 / "exposure-evidence.json"))
    approved = tmp_path / "internet-hosts.csv"  # the person approved every drafted row
    approved.write_text((run0 / "exposure-drafted-hosts.csv").read_text())
    _, d2 = _find(tmp_path, "approved", f"exposure:\n  internet_hosts_file: {approved}\n",
                  "--exposure-claims", str(run0 / "exposure-evidence.json"))
    return run0, d0, d1, d2


def test_the_sample_estate_has_no_tags_and_a_known_truth():
    assets = json.loads((S / "assets.json").read_text())["assets"]
    assert all(a["tags"] == [] for a in assets) and {a["hostname"][0] for a in assets} == set(TRUTH)
    assert len(EXPOSED) == 6 and len(TRUTH) == 10


def test_find_alone_grades_every_rule_but_claims_no_exposure(stages):
    run0, d0, _, _ = stages
    assert len(d0["findings"]) == 10 and not d0["partial"]
    assert _facing(d0) == set() and "REVOKE" not in _grades(d0).values()
    assert any("no asset is marked internet-facing" in w for w in d0["warnings"])
    # a public address is a hint to look, never a verdict
    hinted = {h for h in TRUTH if "PUBLIC_IP" in _codes(d0, h)}
    assert hinted == {"edge-web-01", "shop-app-01", "vpn-gw-01", "brochure-01", "old-ftp-01", "egress-proxy-01"}
    assert len(json.loads((run0 / "exposure-candidates.json").read_text())) == 10


def test_the_exposure_command_checks_every_claim_itself(stages):
    run0 = stages[0]
    ev = json.loads((run0 / "exposure-evidence.json").read_text())
    assert sorted((v["kind"], v["value"]) for v in ev["verified"]) == [
        ("public_dns", "shop.example.net"), ("public_dns", "www.example.net"),
        ("seen_open", "192.88.99.11"), ("seen_open", "192.88.99.12"), ("seen_open", "192.88.99.13")]
    assert sorted(r["reason"] for r in ev["rejected"]) == [
        "does not resolve to this asset",  # the load balancer's address, not the host's
        "last seen 2026-05-01, more than 90 days ago",
        "not a public address of this asset",  # another host's address, on a page's say-so
        "resolves only to private addresses (10.20.2.31)",
        "the internet scan shows no open ports",  # egress-proxy-01: checked, nothing open
        "the internet scan shows no open ports",  # brochure-01: no record at all
        "unknown asset: not a covered asset without exposure evidence"]
    rows = list(csv.DictReader((run0 / "exposure-drafted-hosts.csv").open()))
    assert [r["host"] for r in rows] == ["nat-app-01", "lb-api-01"]


def test_checked_evidence_finds_the_hosts_with_a_public_address_and_nothing_else(stages):
    _, _, d1, _ = stages
    assert _facing(d1) == {"edge-web-01", "shop-app-01", "vpn-gw-01"}
    assert _facing(d1) <= EXPOSED  # no host is wrongly called internet-facing
    assert {h for h, g in _grades(d1).items() if g == "REVOKE"} == _facing(d1)
    assert "JUSTIFICATION_CONTRADICTED" in _codes(d1, "edge-web-01")  # the rule said "internal only"


def test_a_persons_approved_host_list_adds_the_hosts_behind_nat_and_a_load_balancer(stages):
    _, _, _, d2 = stages
    assert _facing(d2) == {"edge-web-01", "shop-app-01", "vpn-gw-01", "nat-app-01", "lb-api-01"}
    assert not _facing(d2) - EXPOSED
    # the one exposed host still missed: a public name on its own address, with no internet-scan record. It stays
    # a REVIEW hint for a person, by design: a name alone does not show a port is open
    assert EXPOSED - _facing(d2) == {"brochure-01"}
    assert _grades(d2)["brochure-01"] == "REVIEW" and "PUBLIC_IP" in _codes(d2, "brochure-01")
