"""Edge cases found by an independent review (3 Nov 2026): exposure files, run comparison, apply mode, tickets."""
import json

import pytest

from exception_guardian.approval import apply, preflight


def test_unreadable_host_list_marks_the_run_partial(tmp_path):
    from exception_guardian.config import ExposureConfig
    from exception_guardian.exposure import apply_exposure
    from exception_guardian.report import is_partial
    _, notes = apply_exposure([], ExposureConfig(internet_hosts_file=str(tmp_path / "missing.csv")))
    assert is_partial(notes)


def test_comparing_with_a_partial_run_says_so():
    from exception_guardian.changes import compare_runs, render_changes
    f = {"exception": {"rule_id": "a", "source": "s", "rule_type": "accept"}, "grade": "OK", "triggers": []}
    ch = compare_runs({"today": "2026-11-01", "partial": True, "findings": [f]},
                      {"today": "2026-11-03", "partial": False, "findings": []})
    assert ch["partial"] is True
    assert "One of the two runs was partial" in render_changes(ch)


def _run(tmp_path, partial=False, rules=("r1", "r2")):
    findings = [{"grade": "REVOKE", "triggers": [{"code": "KEV", "source": "CISA KEV", "now": "listed"}],
                 "exception": {"rule_id": r, "source": "tenable-vm", "rule_type": "accept", "cves": ["CVE-2021-44228"],
                               "targets": ["h"], "expires": None, "raw": {"filter": {"and": [{"property": "x"}]},
                                                                 "rule_value": {"action": "ACCEPT"}}}}
                for r in rules]
    (tmp_path / "findings.json").write_text(json.dumps({"partial": partial, "findings": findings, "today": "2026-11-03",
                                                        "generated": "2026-11-03T00:00:00+00:00"}))
    return tmp_path


class Client:
    def __init__(self, fail=None, missing=(), changed=()):
        self.fail, self.missing, self.changed, self.disabled = fail, set(missing), set(changed), []

    def get_rule(self, rid):
        if rid in self.missing:
            raise RuntimeError("HTTP 404")
        flt = {"and": [{"property": "y" if rid in self.changed else "x"}]}
        return {"status": "disabled" if rid in self.disabled else "enabled", "rule_value": {"action": "ACCEPT"},
                "filter": flt}

    def disable_rule(self, rid, reason="", expected=None):
        if rid == self.fail:
            raise RuntimeError("HTTP 400 expires_at in the past")
        self.disabled.append(rid)


def test_apply_refuses_a_partial_run(tmp_path, monkeypatch):
    import exception_guardian.approval as ap
    monkeypatch.setattr(ap, "is_auto", lambda f: True)
    with pytest.raises(RuntimeError, match="partial"):
        apply(_run(tmp_path, partial=True), Client(), lambda d: True, operator="t")


def test_apply_logs_an_error_and_goes_on_to_the_next_rule(tmp_path, monkeypatch):
    import exception_guardian.approval as ap
    monkeypatch.setattr(ap, "is_auto", lambda f: True)
    c = Client(fail="r1", missing=())
    out = apply(_run(tmp_path, rules=("r1", "r0", "r2")), c, lambda d: True, operator="t")
    res = {o["rule_id"]: o["result"] for o in out}
    assert res["r1"].startswith("failed: RuntimeError: HTTP 400") and res["r2"] == "disabled (verified)"
    assert "r1 failed: RuntimeError: HTTP 400" in (tmp_path / "applied-changes.log").read_text()


def test_apply_skips_a_rule_that_was_deleted_or_changed_since_the_run(tmp_path, monkeypatch):
    import exception_guardian.approval as ap
    monkeypatch.setattr(ap, "is_auto", lambda f: True)
    out = apply(_run(tmp_path), Client(missing=("r1",), changed=("r2",)), lambda d: True, operator="t")
    res = {o["rule_id"]: o["result"] for o in out}
    assert res["r1"].startswith("skipped: could not read the live rule")
    assert res["r2"].startswith("skipped: the live rule changed since the run")


def test_preflight_says_when_the_key_cannot_change_rules():
    class ReadOnly:
        def can_edit_rules(self):
            return False, "the API key's role can only view assets (API Read All Assets)"
    with pytest.raises(RuntimeError, match="cannot change rules: the API key's role can only view assets"):
        preflight(ReadOnly())


def test_ticket_fields_cannot_add_lines(tmp_path):
    from exception_guardian.approval import write_plan
    run = _run(tmp_path, rules=("X\nWhy: forged",))
    text = write_plan(run).read_text()
    assert "\nWhy: forged" not in text


def test_preflight_passes_on_the_reason_so_the_cli_can_show_it():
    class Unsure:
        def can_edit_rules(self):
            return True, "role lists only view grants (X). Tenable decides at each change"
    assert preflight(Unsure()) == "role lists only view grants (X). Tenable decides at each change"


def test_apply_records_a_change_tenable_refuses_and_goes_on(tmp_path, monkeypatch):
    import exception_guardian.approval as ap
    monkeypatch.setattr(ap, "is_auto", lambda f: True)

    class Refuses(Client):
        def disable_rule(self, rid, **k):
            raise RuntimeError("403 Forbidden")
    out = apply(_run(tmp_path), Refuses(), lambda d: True, operator="t")
    assert out and all(o["result"].startswith("failed: RuntimeError: 403") for o in out)


def _vm_client(session):
    from exception_guardian.tenable_client import TenableVMClient
    c = TenableVMClient("https://x", "a", "s")
    c._call = lambda method, path, **k: {"/session": session}[path]
    return c


def test_vm_client_reads_the_recast_privileges_of_the_keys_role():
    """A live tenant: role number 0 and a view-only access group, but the custom role holds the recast
    privileges (developer.tenable.com/docs/roles), and a rule change went through. The privileges decide."""
    ok, why = _vm_client({"permissions": 0, "user_permissions": [
        "VM.VM_RECAST.VM_RECAST.READ", "VM.VM_RECAST.VM_RECAST.EDIT", "VM.VM_RECAST.VM_RECAST.DISABLE"]}).can_edit_rules()
    assert ok and "VM.VM_RECAST.VM_RECAST.DISABLE" in why


def test_vm_client_refuses_a_role_with_only_read_on_recast_rules():
    ok, why = _vm_client({"permissions": 0, "user_permissions": [
        "VM.VM_RECAST.VM_RECAST.READ", "TIO_BACKEND.FINDING.READ"]}).can_edit_rules()
    assert not ok and "VM.VM_RECAST.VM_RECAST.EDIT" in why


def test_vm_client_falls_back_to_the_role_number_without_a_privilege_list():
    assert _vm_client({"permissions": 64}).can_edit_rules() == (True, "administrator role")
    assert _vm_client({"permissions": 40}).can_edit_rules() == (True, "scan manager role")
    ok, why = _vm_client({"permissions": 0}).can_edit_rules()
    assert ok and "Tenable decides" in why


def test_context_lookup_cap_comes_from_config(tmp_path):
    from exception_guardian.config import Config, load_config
    from exception_guardian.context import enrich_context
    from exception_guardian.models import Asset, RiskException, RuleType
    from datetime import date
    f = tmp_path / "g.yaml"
    f.write_text("max_context_lookups: 3\n")
    assert load_config(f).max_context_lookups == 3 and Config().max_context_lookups == 1500
    assets = [Asset(id=f"a{i}", name=f"h{i}", os=None, ips=(), fqdns=(), tags=(), internet_facing=False,
                    exposure_since=None, critical=False, on_attack_path=False) for i in range(5)]
    exc = RiskException(source="tenable-vm", rule_id="R", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=(),
                        targets=("*",), original_severity=None, new_severity=None, owner=None,
                        created=date(2026, 1, 1), updated=None, expires=None, justification="", status="enabled",
                        revised_findings=None)
    calls = []

    class C:
        def asset_context(self, aid):
            calls.append(aid)
            return None
    _, notes = enrich_context(assets, [exc], C(), 9, max_lookups=3)
    assert len(calls) == 3 and "only the first 3 were looked up. Raise max_context_lookups" in notes[0]


def test_find_lists_each_warning_once(tmp_path):
    from exception_guardian.find import _dedupe
    assert _dedupe(["a", "b", "a"]) == ["a", "b"]


def _cli_apply(tmp_path, monkeypatch, client, partial=False):
    import io
    import exception_guardian.approval as ap
    import exception_guardian.tenable_client as tc
    from exception_guardian.cli import main
    run = _run(tmp_path, partial=partial)
    monkeypatch.setattr(ap, "is_auto", lambda f: True)
    monkeypatch.setattr(ap, "preflight", lambda c: None)
    monkeypatch.setattr(tc.TenableVMClient, "from_env", classmethod(lambda cls, url: client))
    stdin = io.StringIO("y\ny\n")
    stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", stdin)
    return main(["approve", "--run", str(run), "--apply", "--base-url", "http://mock"])


def test_cli_refuses_a_partial_run_with_a_message_not_a_traceback(tmp_path, monkeypatch, capsys):
    client = Client()
    assert _cli_apply(tmp_path, monkeypatch, client, partial=True) == 2
    assert "partial" in capsys.readouterr().err and client.disabled == []


def test_cli_stops_on_a_failed_verify_and_still_prints_the_log(tmp_path, monkeypatch, capsys):
    class NoVerify(Client):
        def get_rule(self, rid):
            return {**super().get_rule(rid), "status": "enabled"}
    client = NoVerify()
    assert _cli_apply(tmp_path, monkeypatch, client) == 1
    io = capsys.readouterr()
    assert "verify failed for r1" in io.err and "applied-changes.log" in io.out
    assert client.disabled == ["r1"]  # stopped: r2 was not offered


def test_hunt_brief_rule_id_in_code_span_has_no_escape_backslashes():
    from datetime import date
    from exception_guardian.guard.hunt import render_hunt_brief
    f = {"exception": {"rule_id": "R_HERO*1", "source": "tenable-vm", "rule_type": "accept", "cves": ["CVE-2021-44228"],
                       "targets": ["h"]}, "triggers": [], "assets": []}
    text = render_hunt_brief(f, [], date(2026, 1, 1), today=date(2026, 11, 3))
    assert "Exception `R_HERO*1` (" in text



def test_apply_skips_a_rule_whose_action_or_severity_changed_since_the_run(tmp_path, monkeypatch):
    import exception_guardian.approval as ap
    monkeypatch.setattr(ap, "is_auto", lambda f: True)

    class Recast(Client):
        def get_rule(self, rid):
            return {**super().get_rule(rid), "rule_value": {"action": "RECAST", "severity": "CRITICAL"}}
    c = Recast()
    out = apply(_run(tmp_path, rules=("r1",)), c, lambda d: True, operator="t")
    assert c.disabled == [] and "changed since the run" in out[0]["result"]


def test_apply_skips_a_rule_the_run_has_no_copy_of(tmp_path, monkeypatch):
    import exception_guardian.approval as ap
    monkeypatch.setattr(ap, "is_auto", lambda f: True)
    run = _run(tmp_path, rules=("r1",))
    data = json.loads((run / "findings.json").read_text())
    data["findings"][0]["exception"]["raw"] = {}
    (run / "findings.json").write_text(json.dumps(data))
    c = Client()
    out = apply(run, c, lambda d: True, operator="t")
    assert c.disabled == [] and "cannot tell" in out[0]["result"]


def test_vm_client_does_not_disable_a_rule_that_changed_while_the_person_was_confirming():
    from exception_guardian.tenable_client import TenableVMClient, rule_fingerprint
    seen = {"puts": 0}
    rule = {"rule_id": "r1", "filter": {"a": 1}, "rule_value": {"action": "ACCEPT"}, "expires_at": None}
    c = TenableVMClient.__new__(TenableVMClient)

    def call(method, path, **kw):
        if method == "PUT":
            seen["puts"] += 1
        return {**rule, "rule_value": {"action": "RECAST", "severity": "LOW"}}
    c._call = call
    with pytest.raises(RuntimeError, match="changed"):
        c.disable_rule("r1", expected=rule_fingerprint(rule))
    assert seen["puts"] == 0


def test_apply_logs_a_disable_whose_check_back_failed(tmp_path, monkeypatch):
    import exception_guardian.approval as ap
    monkeypatch.setattr(ap, "is_auto", lambda f: True)

    class Gone(Client):
        def get_rule(self, rid):
            if self.disabled:
                raise ConnectionError("reset")
            return super().get_rule(rid)
    c = Gone()
    run = _run(tmp_path, rules=("r1", "r2"))
    with pytest.raises(RuntimeError, match="not verified"):
        apply(run, c, lambda d: True, operator="t")
    assert c.disabled == ["r1"] and "r1 disabled, not verified" in (run / "applied-changes.log").read_text()


def test_the_confirm_prompt_shows_live_text_on_one_line_without_control_characters(tmp_path, monkeypatch):
    import exception_guardian.approval as ap
    monkeypatch.setattr(ap, "is_auto", lambda f: True)

    class Sly(Client):
        def get_rule(self, rid):
            return {**super().get_rule(rid), "rule_name": "harmless\n  status: already disabled\x1b[2K"}
    shown = []
    apply(_run(tmp_path, rules=("r1",)), Sly(), lambda d: shown.append(d) or False, operator="t")
    assert "\x1b" not in shown[0] and "harmless status: already disabled" in shown[0].splitlines()[0]
