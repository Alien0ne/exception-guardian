"""Fixes from the 3 Nov quality review of the HTML report."""

from exception_guardian.html_report import _context, _grade, _target


def test_a_query_file_outside_the_rules_folder_is_not_read(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-VALUE")
    (tmp_path / "rules" / "R1").mkdir(parents=True)
    for name in ("../../secret.txt", str(secret), "../R2/x.txt"):
        html = _target(tmp_path, "R1", "splunk", {"ok": True, "file": name, "note": None, "error": None})
        assert "TOP-SECRET-VALUE" not in html, name


def test_a_query_file_in_the_rules_folder_is_shown(tmp_path):
    d = tmp_path / "rules" / "R1"
    d.mkdir(parents=True)
    (d / "a.splunk.txt").write_text("index=main whoami")
    html = _target(tmp_path, "R1", "splunk", {"ok": True, "file": "a.splunk.txt", "note": None, "error": None})
    assert "index=main whoami" in html


def test_an_unknown_grade_cannot_break_out_of_the_class_attribute():
    html = _grade('X" onmouseover="alert(1)')
    assert 'onmouseover="' not in html


def test_attack_path_counts_are_escaped():
    a = {"id": "a1", "name": "h", "acr": None, "aes": None, "attack_paths": "<b>3</b>",
         "critical_paths": "<i>1</i>", "context_source": "Tenable One inventory"}
    html = _context([{"assets": [a], "exception": {"rule_id": "R1"}}])
    assert "<b>3</b>" not in html and "<i>1</i>" not in html
