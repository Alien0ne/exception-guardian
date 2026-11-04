"""Manual live test (4 Nov 2026), Claude Code driving /eg-run on a live tenant. Three safe commands were blocked:
an NVD lookup (its URL has /rest/, read as Security Center's API), a key-file existence check (the words ".env
present" inside an echo), and `approve --run out/live; echo $?` (read as a way to build --apply). One asset's tag read
was lost to a dropped connection, which was never retried. The page showed config names in raw `backticks`.
The real attacks these hooks stop must stay blocked."""
import json
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(".claude/hooks").resolve()))
import block_apply  # noqa: E402
import guardrails  # noqa: E402

from exception_guardian.html_report import render_html
from exception_guardian.tenable_client import TenableVMClient


@pytest.mark.parametrize("cmd", [
    'curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-56155"',
    "curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    'curl -s "https://api.first.org/data/v1/epss?cve=CVE-2021-34527"',
    'test -f .env && echo ".env present" || echo ".env absent"',
    "exception-guardian approve --run out/live; echo $?",
    "exception-guardian approve --run out/live 2>&1 | tail -8; echo EXIT=${PIPESTATUS[0]}",
])
def test_safe_commands_from_the_live_run_pass(cmd):
    assert guardrails.check("Bash", {"command": cmd}) is None, cmd
    assert not block_apply.blocked(cmd), cmd


@pytest.mark.parametrize("cmd", [
    "curl -s https://sc.example.internal/rest/acceptRiskRule",
    "curl -s https://nvd.nist.gov.evil.example/rest/x",            # a public host's name inside another host
    "curl -s https://nvd.nist.gov@sc.example.internal/rest/x",     # userinfo trick
    "curl -s https://cloud.tenable.com/assets",
    'echo ".env" | xargs cat',                                     # echo feeding a reader
    "echo hi > .env",
    'cat .env; echo ".env present"',
])
def test_real_attacks_stay_blocked(cmd):
    assert guardrails.check("Bash", {"command": cmd}), cmd


@pytest.mark.parametrize("cmd", [
    "exception-guardian approve --run out/live $A",
    "exception-guardian approve --run out/live; echo $?; exception-guardian approve --run out/live ${X}",
    "exception-guardian approve --run out/live `echo --apply`",
    "exception-guardian approve --run out/live $(printf -- '--ap')ply",
])
def test_expansion_routes_to_apply_stay_blocked(cmd):
    assert block_apply.blocked(cmd), cmd


class _Resp:
    status_code = 200

    def json(self):
        return {"ok": 1}

    def raise_for_status(self):
        pass


def _client(fails, method_seen):
    c = TenableVMClient("https://t.example", "a", "s", sleep=lambda s: None)

    def request(method, url, **kw):
        method_seen.append(method)
        if len(method_seen) <= fails:
            raise requests.ConnectionError("Remote end closed connection without response")
        return _Resp()
    c.session.request = request
    return c


def test_a_dropped_connection_on_a_read_is_retried():
    seen = []
    assert _client(2, seen)._call("GET", "/assets/a1") == {"ok": 1} and len(seen) == 3


def test_a_dropped_connection_on_a_search_is_retried():
    seen = []
    assert _client(1, seen)._call("POST", "/api/v3/assets/host/search", json={}) == {"ok": 1} and len(seen) == 2


def test_a_dropped_connection_on_the_disable_write_is_not_retried():
    seen = []
    with pytest.raises(requests.ConnectionError):
        _client(1, seen)._call("PUT", "/v1/recast/rules/r1", json={})
    assert seen == ["PUT"]


def test_a_connection_that_keeps_dropping_still_fails():
    seen = []
    with pytest.raises(requests.ConnectionError):
        _client(99, seen)._call("GET", "/assets/a1")
    assert len(seen) == 4


def test_warnings_show_config_names_as_code_not_backticks(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps({
        "today": "2026-11-04", "partial": False, "findings": [],
        "warnings": ["exposure: nothing is internet-facing. Set `exposure` in the config"]}))
    page = render_html(tmp_path)
    assert "<code>exposure</code>" in page and "`exposure`" not in page
