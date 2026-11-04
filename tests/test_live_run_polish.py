"""Manual live test (4 Nov 2026), a live run read by Claude Code: report.md listed every matched
asset names for the blanket rule (and 311 CVEs for one rule), pyTenable printed "Starting an unauthenticated
session" on every SC read, and the 200-lookup cap left ~1,200 covered assets without Tenable One context."""
import sys
import types
import warnings
from datetime import date

from exception_guardian.assets import parse_assets
from exception_guardian.config import Config
from exception_guardian.models import GradedException, Grade, RiskException, RuleType
from exception_guardian.report import render_report


def _graded(n_assets, n_cves):
    e = RiskException(source="tenable-vm", rule_id="blanket", rule_type=RuleType.ACCEPT,
                      cves=tuple(f"CVE-2026-{10000 + i}" for i in range(n_cves)), plugin_ids=(), targets=("*",),
                      original_severity=None, new_severity=None, owner=None, created=date(2026, 11, 3), updated=None,
                      expires=None, justification="", status="enabled", revised_findings=None)
    assets = tuple(parse_assets([{"id": f"a{i}", "hostname": [f"host{i}"]} for i in range(n_assets)]))
    return GradedException(e, Grade.REVOKE, (), assets, (), ())


def test_report_md_shortens_long_asset_and_cve_lists():
    md = render_report([_graded(1500, 250)], [], date(2026, 11, 4))
    line = next(l for l in md.splitlines() if l.startswith("- Targets:"))
    assert "host0" in line and "host1499" not in line and "and 1,490 more" in line
    cves = next(l for l in md.splitlines() if l.startswith("- CVEs:"))
    assert "CVE-2026-10000" in cves and "CVE-2026-10249" not in cves and "and 240 more" in cves
    assert "findings.json" in md  # says where the full lists are


def test_report_md_keeps_short_lists_whole():
    md = render_report([_graded(3, 2)], [], date(2026, 11, 4))
    assert "host0, host1, host2" in md and "more" not in next(l for l in md.splitlines() if l.startswith("- Targets:"))


def test_sc_client_signs_in_when_built_so_no_unauthenticated_session(monkeypatch):
    from exception_guardian.readers import tenable_sc
    seen = {}

    class FakeSC:
        def __init__(self, host=None, **kw):
            seen.update(kw)
            if not kw.get("access_key"):
                warnings.warn("Starting an unauthenticated session")
            self.accept_risks = self.recast_risks = types.SimpleNamespace(list=lambda **kw: [])

        def login(self, **kw):
            seen["login"] = True

    monkeypatch.setitem(sys.modules, "tenable.sc", types.SimpleNamespace(TenableSC=FakeSC))
    for k, v in (("TENABLE_SC_HOST", "h"), ("TENABLE_SC_ACCESS_KEY", "ak"), ("TENABLE_SC_SECRET_KEY", "sk")):
        monkeypatch.setenv(k, v)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        tenable_sc.read({})
    assert seen["access_key"] == "ak" and seen["secret_key"] == "sk" and "login" not in seen


def test_lookup_cap_covers_a_lab_sized_tenant():
    assert Config.max_context_lookups >= 1500
