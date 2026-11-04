from dataclasses import replace
from datetime import date

from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.report import md_escape


def test_report_escapes_untrusted_text():
    md = md_escape("<script>alert(1)</script> | `x`\nnext")
    assert "<script>" not in md and "\\|" in md and "\n" not in md


def test_report_then_now_row(tmp_path):
    cfg = replace(load_config("guardian.yaml"), offline=True)
    run_find(cfg, tmp_path, date(2026, 11, 2))
    md = (tmp_path / "report.md").read_text()
    assert "| EPSS_HIGH | 0.00145 | 0.96284 |" in md and "<script>" not in md
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in md  # shown as data, escaped
    assert md.index("R-HERO-001") < md.index("R-REVIEW-005") < md.index("R-OK-004")
