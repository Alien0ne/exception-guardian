"""Elastic as a query target: a shop on Elastic Security gets a Lucene query beside each Sigma rule. It is opt-in
(`siem_targets: [elastic]`), so a run that does not ask for it writes exactly what it wrote before."""

from exception_guardian.config import KNOWN_TARGETS, Config, load_config
from exception_guardian.guard.convert import LABEL, convert_rule

RULE = """
title: Suspicious whoami
id: 11111111-2222-3333-4444-555555555555
status: test
logsource: {category: process_creation, product: windows}
detection:
  sel: {Image|endswith: '\\\\whoami.exe', CommandLine|contains: '/priv'}
  condition: sel
level: high
"""


def test_elastic_is_known_but_not_a_default():
    assert "elastic" in KNOWN_TARGETS and "elastic" not in Config().siem_targets
    assert LABEL["elastic"] == ("Elastic", "Lucene")


def test_config_takes_elastic(tmp_path):
    p = tmp_path / "g.yaml"
    p.write_text("siem_targets: [splunk, elastic]\n")
    assert load_config(p).siem_targets == ("splunk", "elastic")


def test_a_process_rule_becomes_a_lucene_query_on_ecs_fields():
    r = convert_rule(RULE, ("elastic",))["elastic"]
    assert r.ok, r.error
    assert "process.executable" in r.query and "process.command_line" in r.query and "whoami.exe" in r.query


def test_a_rule_elastic_cannot_take_reports_unsupported_not_a_crash():
    bad = RULE.replace("sel: {", "sel: {Nonexistent|re|i|m: 'a(?=b)', ")
    r = convert_rule(bad, ("elastic", "splunk"))
    assert "elastic" in r and (r["elastic"].ok or r["elastic"].error.startswith("unsupported: "))
