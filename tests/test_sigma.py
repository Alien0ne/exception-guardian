from exception_guardian.guard.convert import convert_rule
from exception_guardian.guard.sigmahq import generic_rules, rules_for_cve
from exception_guardian.guard.validate import validate_rule

GOOD = ("title: t\nid: 2b3c7d2e-1111-4a1a-9a1a-000000000001\nstatus: experimental\n"
        "logsource: {category: process_creation, product: linux}\ndetection: {sel: {Image|endswith: /sh}, condition: sel}\n")


def test_index_has_crushftp_not_livewire():
    assert rules_for_cve("CVE-2025-31161")[0].bundled_path is not None
    assert rules_for_cve("CVE-2025-54068") == []


def test_bundled_rules_keep_author():
    refs = generic_rules("linux") + generic_rules("windows") + rules_for_cve("CVE-2025-31161")[:1]
    assert len(refs) == 3
    for ref in refs:
        assert "author:" in ref.bundled_path.read_text() and ref.url.startswith("https://github.com/SigmaHQ/sigma/blob/ccbb036")


def test_generic_rules_unknown_os():
    assert generic_rules(None) == [] and generic_rules("aix") == []


def test_validate_flags_draft_without_references():
    assert any("references" in e for e in validate_rule(GOOD, drafted=True))
    assert validate_rule(GOOD, drafted=False) == []


def test_validate_flags_draft_status_and_multi_doc():
    y = GOOD.replace("experimental", "stable") + "references: [https://example.com]\n"
    assert any("status" in e for e in validate_rule(y, drafted=True))
    two = GOOD + "references: [https://example.com]\n---\n" + GOOD.replace("0001", "0009") + "references: [https://example.com]\n"
    assert any("one rule" in e for e in validate_rule(two, drafted=True))


def test_validate_missing_detection():
    assert any("detection" in e for e in validate_rule("title: t\nid: x\nlogsource: {product: linux}\n", drafted=False))


def test_validate_rejects_garbage():
    assert validate_rule("title: [unclosed", drafted=True)


def test_convert_all_targets_process_creation():
    y = generic_rules("linux")[0].bundled_path.read_text()
    res = convert_rule(y, ("splunk", "sentinel", "defender"))
    assert all(r.ok and r.query for r in res.values()), res


def test_convert_webserver_unsupported_on_defender():
    y = ("title: t\nid: 2b3c7d2e-1111-4a1a-9a1a-000000000002\nstatus: experimental\nreferences: [https://example.com]\n"
         "logsource: {category: webserver}\ndetection: {sel: {cs-method: POST, cs-uri-stem|contains: /livewire/update}, condition: sel}\n")
    res = convert_rule(y, ("splunk", "defender"))
    assert res["splunk"].ok and not res["defender"].ok and res["defender"].error.startswith("unsupported")
