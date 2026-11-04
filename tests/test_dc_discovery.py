"""DC discovery (4 Nov 2026): the live run left five SigmaHQ placeholders (DC names and IPs) on stand-ins because no
step could find the domain controllers, and Claude may not call Tenable itself. The `dcs` command reads the scan
evidence (read-only), lists the DCs with the evidence for each, and only on the human's yes (`--use`) writes the
values for this run, which guard then uses."""
import json
import os
from dataclasses import replace
from pathlib import Path

import yaml

from exception_guardian.dcs import find_dcs, parse_rootdse, placeholders_from

KERB, LDAP, ROOTDSE, ADCONF, DNS = "43829", "20870", "25701", "170631", "58181"


def _rootdse(host, cn, dom):
    dc = ",".join(f"DC={p}" for p in dom.split("."))
    return (f"[+]-namingContexts:\n|  {dc}\n[+]-dnsHostName:\n|  {host}\n[+]-serverName:\n"
            f"|  CN={cn},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{dc}\n")


class FakeVM:
    def __init__(self, assets, plugins, outputs):
        self.assets, self.plugins, self.outputs, self.calls = assets, plugins, outputs, []

    def list_assets(self):
        return self.assets

    def asset_plugin_ids(self, aid):
        self.calls.append(("plugins", aid))
        return set(self.plugins.get(aid, ()))

    def plugin_output(self, aid, pid):
        self.calls.append(("output", aid, pid))
        return self.outputs.get((aid, pid), "")


def _a(aid, name, os_, ip):
    return {"id": aid, "hostname": [name], "operating_system": [os_], "ipv4": [ip], "fqdn": [f"{name}.corp.example.com"]}


def _lab():
    assets = [_a("1", "dc01", "Microsoft Windows Server 2019 Standard", "192.0.2.10"),
              _a("2", "dc02", "Microsoft Windows Server 2022 Standard", "192.0.2.11"),
              _a("3", "files", "Microsoft Windows Server 2016 Standard", "192.0.2.20"),
              _a("4", "ldapbox", "Microsoft Windows Server 2016 Standard", "192.0.2.30"),
              _a("5", "web", "Linux Kernel 5.x on Ubuntu", "192.0.2.40")]
    plugins = {"1": {KERB, LDAP, ROOTDSE, DNS}, "2": {KERB, LDAP, ROOTDSE, ADCONF}, "3": {DNS}, "4": {KERB, LDAP},
               "5": {KERB, LDAP}}
    outputs = {("1", ROOTDSE): _rootdse("dc01.corp.example.com", "DC01", "corp.example.com"),
               ("2", ROOTDSE): _rootdse("DC02.corp.example.com", "DC02", "corp.example.com"),
               ("2", ADCONF): "Distinguished Name : CN=DC02,OU=Domain Controllers,DC=corp\nDomain Role        : "
                              "PrimaryDomainController\n"}
    return FakeVM(assets, plugins, outputs)


def test_rootdse_output_gives_the_host_name_and_the_server_object():
    host, server = parse_rootdse(_rootdse("dc01.corp.example.com", "DC01", "corp.example.com"))
    assert host == "dc01.corp.example.com" and server.startswith("CN=DC01,CN=Servers,")


def test_kerberos_ldap_and_a_sites_server_object_confirm_a_dc():
    vm = _lab()
    found = {d["name"]: d for d in find_dcs(vm)}
    assert found["dc01"]["confirmed"] and found["dc01"]["account"] == "DC01$"
    assert found["dc01"]["ips"] == ["192.0.2.10"] and found["dc01"]["dns_host_name"] == "dc01.corp.example.com"
    assert found["dc01"]["domain"] == "corp.example.com"
    assert any("Kerberos" in e for e in found["dc01"]["evidence"]) and any("Sites" in e for e in found["dc01"]["evidence"])
    assert any("PrimaryDomainController" in e for e in found["dc02"]["evidence"])
    assert "files" not in found                                 # DNS alone is not a DC
    assert found["ldapbox"]["confirmed"] is False               # Kerberos and LDAP, but no proof of the DC role
    assert all(c[1] != "5" for c in vm.calls)                   # only Windows servers are looked up


def test_only_confirmed_dcs_become_placeholder_values():
    ph = placeholders_from(find_dcs(_lab()))
    assert ph["dc_machine_accounts"] == ["DC01$", "DC02$"] == ph["DC-MACHINE-NAME"]
    assert ph["dc_ip_addresses"] == ["192.0.2.10", "192.0.2.11"] == ph["legit_ips"]
    assert ph["known_cdcs"] == ["dc01.corp.example.com", "DC02.corp.example.com", "192.0.2.10", "192.0.2.11"]
    assert placeholders_from([{"confirmed": False, "account": "X$", "ips": ["192.0.2.9"]}]) == {}


def test_the_client_lookups_are_reads(monkeypatch):
    from exception_guardian.tenable_client import TenableVMClient
    c = TenableVMClient("https://vm.example.com", "a", "s")
    seen = []
    def fake(method, path, **kw):
        seen.append((method, path))
        return {"vulnerabilities": [{"plugin_id": 43829}], "outputs": [{"plugin_output": "x"}, {"plugin_output": "y"}]}
    monkeypatch.setattr(c, "_call", fake)
    assert c.asset_plugin_ids("a b") == {"43829"} and c.plugin_output("a b", "25701") == "x\ny"
    assert all(m == "GET" for m, _ in seen) and "/workbenches/assets/a%20b/vulnerabilities" in seen[0][1]


def _run_dir(tmp_path, config):
    (tmp_path / "findings.json").write_text(json.dumps({"today": "2026-11-04", "findings": [], "config": str(config)}))
    return tmp_path


def test_dcs_offline_looks_nothing_up(tmp_path, capsys):
    from exception_guardian.cli import main
    run = _run_dir(tmp_path, Path("guardian.yaml").resolve())
    assert main(["dcs", "--run", str(run)]) == 0
    assert "nothing looked up" in capsys.readouterr().out and not (run / "dc-candidates.json").exists()


def test_use_writes_this_run_s_values_only_from_confirmed_dcs(tmp_path, capsys):
    from exception_guardian.cli import main
    run = _run_dir(tmp_path, Path("guardian.yaml").resolve())
    (run / "dc-candidates.json").write_text(json.dumps({"dcs": find_dcs(_lab())}))
    assert main(["dcs", "--run", str(run), "--use"]) == 0
    ph = yaml.safe_load((run / "placeholders.found.yaml").read_text())
    assert ph["dc_ip_addresses"] == ["192.0.2.10", "192.0.2.11"]
    assert "placeholders.local.yaml" in capsys.readouterr().out   # how to keep them for later runs


def test_use_with_no_confirmed_dc_writes_nothing(tmp_path):
    from exception_guardian.cli import main
    run = _run_dir(tmp_path, Path("guardian.yaml").resolve())
    (run / "dc-candidates.json").write_text(json.dumps({"dcs": [{"name": "x", "confirmed": False}]}))
    assert main(["dcs", "--run", str(run), "--use"]) == 2 and not (run / "placeholders.found.yaml").exists()


def test_guard_uses_the_run_s_found_values_but_the_config_wins(tmp_path):
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import placeholders_for_run
    cfg = replace(load_config("guardian.yaml"), placeholders={"dc_ip_addresses": ["198.51.100.1"]})
    (tmp_path / "placeholders.found.yaml").write_text(yaml.safe_dump(
        {"dc_ip_addresses": ["192.0.2.10"], "dc_machine_accounts": ["DC01$"]}))
    ph = placeholders_for_run(tmp_path, cfg)
    assert ph == {"dc_ip_addresses": ["198.51.100.1"], "dc_machine_accounts": ["DC01$"]}
    assert placeholders_for_run(tmp_path / "none", cfg) == cfg.placeholders


def test_guard_run_picks_the_found_values_up(tmp_path):
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import run_guard
    f = {"exception": {"source": "tenable-vm", "rule_id": "zl", "rule_type": "accept", "cves": ["CVE-2020-1472"],
                       "plugin_ids": [], "targets": ["dc01"], "created": "2026-11-01", "expires": None,
                       "justification": "", "status": "enabled", "revised_findings": 1, "owner": None},
         "grade": "REVOKE", "triggers": [{"code": "KEV", "grade": "REVOKE", "then": None, "now": "x", "source": "s"}],
         "assets": [], "intel": [], "notes": []}
    (tmp_path / "findings.json").write_text(json.dumps({"today": "2026-11-04", "partial": False, "warnings": [],
                                                       "findings": [f]}))
    (tmp_path / "placeholders.found.yaml").write_text(yaml.safe_dump({"DC-MACHINE-NAME": ["DC01$"]}))
    run_guard(tmp_path, tmp_path / "nodrafts", replace(load_config("guardian.yaml"), placeholders={}))
    queries = "".join(p.read_text() for p in (tmp_path / "rules").rglob("*.txt"))
    assert "DC01$" in queries


def test_claude_cannot_write_the_found_values_or_the_candidates_itself():
    import subprocess
    import sys

    def run(tool, inp):  # in harness mode (EG_HARNESS), as /eg-run is tested
        env = {**os.environ, "CLAUDE_PROJECT_DIR": os.getcwd(), "EG_HARNESS": "1"}
        p = subprocess.run([sys.executable, ".claude/hooks/guardrails.py"], capture_output=True, text=True, env=env,
                           input=json.dumps({"tool_name": tool, "tool_input": inp}), timeout=10)
        return p.returncode, p.stderr
    for f in ("out/live/placeholders.found.yaml", "out/live/dc-candidates.json"):
        code, err = run("Write", {"file_path": os.path.join(os.getcwd(), f)})
        assert code == 2 and "the code writes" in err, f


def test_eg_run_looks_up_dcs_and_asks_before_using_them():
    text = Path(".claude/commands/eg-run.md").read_text()
    assert "exception-guardian dcs --run" in text and "--use" in text
    skill = Path("SKILL.md").read_text()
    assert "dcs --run" in skill and "never guess" in skill.lower()
    assert "`dcs`" in Path("references/commands.md").read_text()


def test_finish_lists_only_next_steps_that_apply():
    """A live run told the person to check an empty exposure-drafted-hosts.csv and to create placeholders.local.yaml by
    hand, though the run can now find the DCs itself."""
    fin = Path("SKILL.md").read_text().split("## Finish", 1)[1].split("\n## ", 1)[0]
    assert "only when it has rows" in fin
    assert "placeholders.found.yaml" in fin and "placeholders.local.yaml" in fin
    assert "never tell the person to find the dcs by hand" in fin.replace("\n", " ").lower()


def _zl_run(tmp_path, cves=("CVE-2020-1472",)):
    f = {"exception": {"source": "tenable-vm", "rule_id": "zl", "rule_type": "accept", "cves": list(cves),
                       "plugin_ids": [], "targets": ["dc01"], "created": "2026-11-01", "expires": None,
                       "justification": "", "status": "enabled", "revised_findings": 1, "owner": None},
         "grade": "REVOKE", "triggers": [{"code": "KEV", "grade": "REVOKE", "then": None, "now": "x", "source": "s"}],
         "assets": [], "intel": [], "notes": []}
    (tmp_path / "findings.json").write_text(json.dumps({"today": "2026-11-04", "partial": False, "warnings": [],
                                                       "findings": [f]}))
    return tmp_path


def test_hunt_brief_lists_the_dcs_its_rules_use_and_where_they_came_from(tmp_path):
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import run_guard
    run = _zl_run(tmp_path)
    (run / "placeholders.found.yaml").write_text(yaml.safe_dump({"DC-MACHINE-NAME": ["DC01$", "DC02$"]}))
    run_guard(run, run / "nodrafts", replace(load_config("guardian.yaml"), placeholders={}))
    brief = (run / "hunt-briefs" / "zl.md").read_text().replace("\\", "")
    infra = brief.split("## Known infrastructure", 1)[1].split("\n## ", 1)[0]
    assert "DC01$" in infra and "DC02$" in infra and "DC lookup" in infra
    prompt = brief.split("starting prompt", 1)[1]
    assert "DC01$" in prompt and "expected" in prompt


def test_config_values_are_named_as_the_config_s(tmp_path):
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import run_guard
    run = _zl_run(tmp_path)
    run_guard(run, run / "nodrafts", replace(load_config("guardian.yaml"), placeholders={"DC-MACHINE-NAME": ["DC09$"]}))
    infra = (run / "hunt-briefs" / "zl.md").read_text().split("## Known infrastructure", 1)[1].split("\n## ", 1)[0]
    assert "DC09$" in infra.replace("\\", "") and "your config" in infra


def test_a_brief_without_dc_rules_has_no_infrastructure_section(tmp_path):
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import run_guard
    run = _zl_run(tmp_path, cves=("CVE-2021-41773",))
    run_guard(run, run / "nodrafts", replace(load_config("guardian.yaml"), placeholders={"DC-MACHINE-NAME": ["DC09$"]}))
    brief = (run / "hunt-briefs" / "zl.md").read_text()
    assert "Known infrastructure" not in brief and "DC09" not in brief


def test_unset_dc_placeholders_are_said_in_the_brief(tmp_path):
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import run_guard
    run = _zl_run(tmp_path)
    run_guard(run, run / "nodrafts", replace(load_config("guardian.yaml"), placeholders={}))
    infra = (run / "hunt-briefs" / "zl.md").read_text().split("## Known infrastructure", 1)[1].split("\n## ", 1)[0]
    assert "not set" in infra and "dcs --run" in infra


def _ws(label, user, ip, note):
    return json.dumps({"_logsource": "windows/security", "_label": label,
                       "_attack": ["CVE-2026-54121"] if label == "attack" else [], "_note": note,
                       "_source": "https://example.com/advisory", "EventID": 4624, "LogonType": 3,
                       "TargetUserName": user, "IpAddress": ip, "Status": "0x0"})


def test_samples_are_scored_against_the_sample_world_dcs_not_the_real_ones(tmp_path):
    """A live run: with the real DCs set, the DC rules caught 0 of 1, because samples must use example names (DC-02$)."""
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import run_guard
    run = _zl_run(tmp_path, cves=("CVE-2026-54121",))
    (run / "samples").mkdir()
    (run / "samples" / "windows-security.jsonl").write_text("\n".join([
        _ws("attack", "DC-02$", "198.51.100.66", "the DC's machine account logs on from a workstation address"),
        _ws("benign", "DC-02$", "192.0.2.11", "a DC logs on to its replication partner")]) + "\n")
    real = {"dc_machine_accounts": ["DC09$"], "dc_ip_addresses": ["10.0.0.9"]}
    g = run_guard(run, run / "nodrafts", replace(load_config("guardian.yaml"), placeholders=real))
    rule = next(r for r in g["zl"]["rules"] if r["title"].startswith("DC Machine Account Network Logon"))
    t = rule["tested"]
    assert (t["attack_hits"], t["attack_total"], t["benign_hits"]) == (1, 1, 0), t
    query = (run / "rules" / "zl" / rule["conversions"]["splunk"]["file"]).read_text()
    assert "DC09$" in query and "DC-02$" not in query          # the SIEM query keeps the real DCs


def test_the_sample_brief_names_the_sample_world_dcs(tmp_path):
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import run_guard
    run = _zl_run(tmp_path, cves=("CVE-2026-54121",))
    run_guard(run, run / "nodrafts", replace(load_config("guardian.yaml"), placeholders={"dc_machine_accounts": ["DC09$"]}))
    brief = (run / "sample-briefs" / "windows-security.md").read_text()
    assert "DC-01$" in brief and "192.0.2.10" in brief and "DC09" not in brief
    assert "never from the real tenant" in brief


def test_a_brief_whose_rules_use_no_dc_values_does_not_name_dcs(tmp_path):
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import run_guard
    run = _zl_run(tmp_path, cves=("CVE-2021-41773",))
    run_guard(run, run / "nodrafts", replace(load_config("guardian.yaml"), placeholders={}))
    for b in (run / "sample-briefs").glob("*.md"):
        assert "DC-01$" not in b.read_text(), b


def test_dc_addresses_also_match_the_ipv4_mapped_form_kerberos_logs(tmp_path):
    """4768/4769 log IpAddress as ::ffff:a.b.c.d. A DC list of plain addresses missed every DC's own TGT (run #4)."""
    from exception_guardian.config import load_config
    from exception_guardian.guard.run import run_guard
    run = _zl_run(tmp_path, cves=("CVE-2026-54121",))
    (run / "samples").mkdir()
    tgt = lambda label, ip: json.dumps({"_logsource": "windows/security", "_label": label, "_note": "a TGT",
                                        "_attack": ["CVE-2026-54121"] if label == "attack" else [],
                                        "_source": "https://example.com/a", "EventID": 4768, "Status": "0x0",
                                        "TargetUserName": "DC-01$", "ServiceName": "krbtgt", "IpAddress": ip})
    (run / "samples" / "windows-security.jsonl").write_text(
        tgt("attack", "::ffff:198.51.100.66") + "\n" + tgt("benign", "::ffff:192.0.2.10") + "\n")
    real = {"dc_machine_accounts": ("DC09$",), "dc_ip_addresses": ("10.0.0.9",)}  # load_config gives tuples
    g = run_guard(run, run / "nodrafts", replace(load_config("guardian.yaml"), placeholders=real))
    rule = next(r for r in g["zl"]["rules"] if r["title"].startswith("DC Machine Account TGT"))
    assert (rule["tested"]["attack_hits"], rule["tested"]["benign_hits"]) == (1, 0), rule["tested"]
    query = (run / "rules" / "zl" / rule["conversions"]["splunk"]["file"]).read_text()
    assert "::ffff:10.0.0.9" in query and "10.0.0.9" in query.replace("::ffff:10.0.0.9", "")
