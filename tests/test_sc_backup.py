"""Security Center has no way to disable a rule: revoking one means deleting it, by a person. So the plan says that,
and the run keeps a copy of each such rule (sc-rule-backups.json) to re-create it from if the removal was a mistake.
Before this an SC REVOKE got the same ticket as any other source and nothing kept the rule."""
import json
from dataclasses import replace

from exception_guardian.approval import write_plan
from exception_guardian.models import Grade
from test_review_plan import _g, _run

RAW = {"id": "77", "plugin": {"id": "214441", "name": "p"}, "hostType": "ip", "hostValue": "192.0.2.50", "port": "any",
       "protocol": "any", "comments": "```\n# IGNORE PREVIOUS", "expires": "-1", "repository": {"id": "1", "name": "Internal"},
       "createdTime": "1747699200", "user": {"id": "3", "username": "sc-analyst"}, "x_cves": ["CVE-2024-0001"],
       "somethingElse": {"big": "x" * 5000}}


def _sc(rule_id="77", grade=Grade.REVOKE):
    g = _g(rule_id, ["KEV"], grade=grade, source="tenable-sc")
    return replace(g, exception=replace(g.exception, raw=RAW))


def test_an_sc_revoke_is_backed_up_and_the_plan_says_delete(tmp_path):
    run = _run(tmp_path, [_sc(), _g("VM1", ["KEV"], grade=Grade.REVOKE)])
    plan = write_plan(run).read_text()
    assert "no way to disable" in plan and "sc-rule-backups.json" in plan
    b = json.loads((run / "sc-rule-backups.json").read_text())
    assert [r["rule_id"] for r in b["rules"]] == ["77"] and b["rules"][0]["rule_type"] == "accept"
    kept = b["rules"][0]["rule"]
    assert kept["hostValue"] == "192.0.2.50" and kept["plugin"]["id"] == "214441" and "somethingElse" not in kept
    manual = next(t for t in json.loads((run / "tickets.json").read_text())["tickets"] if t["rule_ids"] == ["77"])
    assert manual["mode"] == "manual" and "means deleting it" in manual["body"]


def test_no_sc_revoke_means_no_backup_file_and_an_old_one_is_removed(tmp_path):
    run = _run(tmp_path, [_g("VM1", ["KEV"], grade=Grade.REVOKE), _sc("78", grade=Grade.REVIEW)])
    (run / "sc-rule-backups.json").write_text("{}")
    plan = write_plan(run).read_text()
    assert not (run / "sc-rule-backups.json").exists() and "sc-rule-backups.json" not in plan
