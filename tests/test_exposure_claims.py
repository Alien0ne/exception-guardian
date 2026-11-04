"""Map exposure: the agent proposes, the code verifies. Claims are untrusted; only what the verifier re-derives
itself (DNS it resolved, an internet scan it fetched) is used, and document claims only become a draft host list
for a person to approve."""
import csv
import json
from dataclasses import replace
from datetime import date

from exception_guardian.cli import main
from exception_guardian.config import ExposureConfig, load_config
from exception_guardian.exposure import apply_exposure
from exception_guardian.exposure_claims import candidates, verify_claims
from exception_guardian.find import run_find

TODAY = date(2026, 11, 2)
ASSET = {"id": "a1", "name": "app-7", "ips": ["10.2.0.7", "9.9.9.9"], "fqdns": ["shop.example.net"],
         "internet_facing": False, "public_ips": ["9.9.9.9"]}
FINDINGS = {"today": "2026-11-02", "findings": [{"assets": [ASSET, {**ASSET, "id": "a2", "name": "web",
                                                                   "internet_facing": True}]}]}


def _resolve(name):
    return {"shop.example.net": ["9.9.9.9"], "intranet.example.net": ["10.2.0.7"]}.get(name, [])


def _shodan(ip):
    return {"9.9.9.9": {"ports": [443, 3389], "last_update": "2026-10-30T08:00:00"}}.get(ip)


def _verify(claims, shodan=_shodan):
    return verify_claims(claims, FINDINGS, TODAY, resolve=_resolve, internet_scan=shodan)


def test_candidates_are_covered_assets_without_exposure_evidence():
    assert [c["id"] for c in candidates(FINDINGS)] == ["a1"]


def test_dns_claim_is_verified_by_resolving_it_ourselves():
    v, drafted, rejected = _verify([{"asset_id": "a1", "kind": "dns", "value": "shop.example.net",
                                     "source": "crt.sh certificate 2026-09-01"}])
    assert v == [{"asset_id": "a1", "kind": "public_dns", "value": "shop.example.net",
                  "evidence": "public DNS name shop.example.net resolves to 9.9.9.9 (agent-found, verified 2026-11-02)"}]
    assert drafted == [] and rejected == []


def test_dns_to_a_private_address_or_another_host_is_rejected():
    _, _, rejected = _verify([{"asset_id": "a1", "kind": "dns", "value": "intranet.example.net", "source": "x"},
                              {"asset_id": "a1", "kind": "dns", "value": "other.example.org", "source": "x"}])
    assert [r["reason"] for r in rejected] == ["resolves only to private addresses (10.2.0.7)",
                                              "does not resolve to this asset"]


def test_internet_scan_claim_is_verified_by_fetching_it_ourselves():
    v, _, _ = _verify([{"asset_id": "a1", "kind": "internet_scan", "value": "9.9.9.9", "source": "Shodan"}])
    assert v[0]["kind"] == "seen_open"
    assert v[0]["evidence"] == ("seen open from the internet on 2026-10-30: ports 443, 3389 "
                                "(agent-found, verified 2026-11-02)")


def test_scan_claims_without_a_scan_source_or_stale_are_rejected():
    _, _, r = _verify([{"asset_id": "a1", "kind": "internet_scan", "value": "9.9.9.9", "source": "s"}], shodan=None)
    assert r[0]["reason"].startswith("cannot verify: no internet scan source")
    old = lambda ip: {"ports": [22], "last_update": "2026-01-01T00:00:00"}  # noqa: E731
    _, _, r = _verify([{"asset_id": "a1", "kind": "internet_scan", "value": "9.9.9.9", "source": "s"}], shodan=old)
    assert r[0]["reason"] == "last seen 2026-01-01, more than 90 days ago"
    _, _, r = _verify([{"asset_id": "a1", "kind": "internet_scan", "value": "10.2.0.7", "source": "s"}])
    assert r[0]["reason"] == "not a public address of this asset"


def test_untrusted_claims_are_rejected_not_trusted():
    v, d, r = _verify([{"asset_id": "zz", "kind": "dns", "value": "shop.example.net", "source": "x"},
                       {"asset_id": "a1", "kind": "trust_me", "value": "x", "source": "x"},
                       {"asset_id": "a1", "kind": "dns", "value": "shop.example.net; rm -rf /", "source": "x"},
                       "not even a dict"])
    assert v == [] and d == [] and len(r) == 4


def test_document_claims_become_a_draft_for_a_person_never_evidence():
    v, drafted, r = _verify([{"asset_id": "a1", "kind": "document", "value": "app-7",
                              "source": "fw-export.csv line 12: NAT 203.0.113.5:443 -> 10.2.0.7"}])
    assert v == [] and r == []
    assert drafted == [{"host": "app-7", "source": "fw-export.csv line 12: NAT 203.0.113.5:443 -> 10.2.0.7"}]


def test_verified_evidence_drives_grading_through_find(tmp_path):
    ev = tmp_path / "exposure-evidence.json"
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path / "r0", TODAY)
    d = json.loads((tmp_path / "r0/findings.json").read_text())
    ftp = next(a for f in d["findings"] for a in f["assets"] if a["name"] == "ftp-01")
    ev.write_text(json.dumps({"verified": [{"asset_id": ftp["id"], "kind": "seen_open", "value": "192.0.2.30",
                                            "evidence": "seen open from the internet on 2026-10-30: ports 21 "
                                                        "(agent-found, verified 2026-11-02)"}], "rejected": []}))
    cfg = replace(load_config("guardian.yaml"), offline=True, exposure=ExposureConfig(claims_file=str(ev)))
    run_find(cfg, tmp_path / "r1", TODAY)
    d = json.loads((tmp_path / "r1/findings.json").read_text())
    trig = [t for f in d["findings"] for t in f["triggers"] if t["code"] == "INTERNET_FACING"]
    assert any("agent-found, verified" in t["source"] and "ftp-01" in t["source"] for t in trig)


def test_public_dns_evidence_is_a_review_hint(tmp_path):
    from exception_guardian.assets import parse_assets
    a = parse_assets([{"id": "a1", "hostname": ["app-7"], "ipv4": ["10.2.0.7"]}])
    ev = tmp_path / "e.json"
    ev.write_text(json.dumps({"verified": [{"asset_id": "a1", "kind": "public_dns", "value": "shop.example.net",
                                            "evidence": "public DNS name shop.example.net resolves to 9.9.9.9"}]}))
    out, _ = apply_exposure(a, ExposureConfig(claims_file=str(ev)))
    assert not out[0].internet_facing and out[0].public_dns == ("shop.example.net",)


def test_exposure_command_writes_evidence_and_draft(tmp_path, monkeypatch):
    from exception_guardian import exposure_claims as m
    run = tmp_path / "r"
    assert main(["find", "--offline", "--out", str(run), "--today", "2026-11-02"]) == 0
    cands = json.loads((run / "exposure-candidates.json").read_text())
    assert cands and all(not c["internet_facing"] for c in cands)
    (run / "exposure-claims.json").write_text(json.dumps([
        {"asset_id": cands[0]["id"], "kind": "document", "value": cands[0]["name"], "source": "lb export"}]))
    monkeypatch.setattr(m, "resolve_dns", lambda n: [])
    assert main(["exposure", "--run", str(run)]) == 0
    out = json.loads((run / "exposure-evidence.json").read_text())
    assert out["verified"] == [] and out["rejected"] == []
    rows = list(csv.DictReader((run / "exposure-drafted-hosts.csv").open()))
    assert rows == [{"host": cands[0]["name"], "source": "lb export"}]


def test_a_failed_shodan_read_never_writes_the_key(tmp_path, monkeypatch):
    """Review of src, 4 Nov 2026: Shodan takes its key in the URL, and requests puts the URL in its error, so a 401
    copied part of SHODAN_API_KEY into the rejection reason in exposure-evidence.json."""
    import requests
    from exception_guardian import exposure_claims
    key = "fake-shodan-key-not-real"
    monkeypatch.setenv("SHODAN_API_KEY", key)

    def get(url, params=None, timeout=None):
        r = requests.Response()
        r.status_code, r.reason = 401, "Unauthorized"
        r.url = requests.Request("GET", url, params=params).prepare().url
        return r
    monkeypatch.setattr(requests, "get", get)
    run = tmp_path / "run"
    run.mkdir()
    (run / "findings.json").write_text(json.dumps(FINDINGS))
    claims = tmp_path / "claims.json"
    claims.write_text(json.dumps([{"asset_id": "a1", "kind": "internet_scan", "value": "9.9.9.9", "source": "s"}]))
    assert exposure_claims.run_exposure(run, claims)["rejected"] == 1
    out = (run / "exposure-evidence.json").read_text()
    assert "401" in out and key[:8] not in out and "key=" not in out
