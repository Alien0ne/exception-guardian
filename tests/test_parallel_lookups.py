"""Manual live test (4 Nov 2026): find sat silent for minutes on a live tenant, one request at a time: a plugin
lookup per plugin, a finding count per rule, two asset lookups per covered asset. Lookups now run several at once,
results stay in order, and long ones print progress so the run never looks hung."""
import threading
from datetime import date

import pytest

from exception_guardian.assets import parse_assets
from exception_guardian.context import enrich_context
from exception_guardian.models import RiskException, RuleType
from exception_guardian.parallel import WORKERS, parallel_map
from exception_guardian.readers import count_rule_findings, enrich_plugin_cves


class _Pair:
    """The first two calls must be in flight together: one at a time, the barrier times out and the test fails."""

    def __init__(self):
        self.barrier, self.n, self.lock = threading.Barrier(2, timeout=5), 0, threading.Lock()

    def wait(self):
        with self.lock:
            self.n += 1
            first_two = self.n <= 2
        if first_two:
            self.barrier.wait()


def _exc(rid, **kw):
    base = dict(source="tenable-vm", rule_id=rid, rule_type=RuleType.ACCEPT, cves=(), plugin_ids=(),
                targets=("*",), original_severity=None, new_severity=None, owner=None, created=date(2026, 1, 1),
                updated=None, expires=None, justification="x", status="enabled", revised_findings=None, raw={})
    return RiskException(**{**base, **kw})


def test_parallel_map_runs_lookups_together_and_keeps_their_order():
    pair = _Pair()

    def fn(x):
        pair.wait()
        if x == 3:
            raise ValueError("boom")
        return x * 10

    out = parallel_map(fn, list(range(6)))
    assert out[:3] == [0, 10, 20] and isinstance(out[3], ValueError) and out[4:] == [40, 50]
    assert WORKERS > 1


def test_long_lookups_print_progress(capsys):
    parallel_map(lambda x: x, list(range(60)), label="finding counts")
    err = capsys.readouterr().err
    assert "finding counts: 60/60" in err


def test_short_lookups_stay_quiet(capsys):
    parallel_map(lambda x: x, [1, 2, 3], label="finding counts")
    assert capsys.readouterr().err == ""


def test_finding_counts_run_together():
    pair = _Pair()

    def counter(raw):
        pair.wait()
        return raw["n"], False

    rules = [_exc(f"r{i}", raw={"n": i}) for i in range(5)]
    out, warn = count_rule_findings(rules, counter)
    assert [e.revised_findings for e in out] == [0, 1, 2, 3, 4] and warn == []


def test_plugin_lookups_run_together_once_per_plugin():
    pair, calls = _Pair(), []

    def lookup(pid):
        calls.append(pid)
        pair.wait()
        return (f"CVE-2025-{pid}",)

    rules = [_exc("a", plugin_ids=("1",)), _exc("b", plugin_ids=("2",)), _exc("c", plugin_ids=("1", "2"))]
    out, warn = enrich_plugin_cves(rules, lookup)
    assert [e.cves for e in out] == [("CVE-2025-1",), ("CVE-2025-2",), ("CVE-2025-1", "CVE-2025-2")]
    assert sorted(calls) == ["1", "2"] and warn == []


def test_asset_lookups_run_together():
    pair = _Pair()

    class Client:
        def asset_context(self, aid):
            pair.wait()
            return {"acr": 10, "aes": 900, "paths": 1, "critical_paths": 0, "source": "Tenable One inventory"}

        def asset_tags(self, aid):
            return []

    assets = parse_assets([{"id": f"a{i}", "hostname": [f"h{i}"], "ipv4": [f"10.0.0.{i + 1}"]} for i in range(4)])
    out, notes = enrich_context(assets, [_exc("r")], Client(), 9)
    assert [a.acr for a in out] == [10, 10, 10, 10] and notes == []


@pytest.mark.parametrize("bad", [0, -1])
def test_a_bad_worker_count_falls_back_to_one(bad):
    assert parallel_map(lambda x: x + 1, [1, 2], workers=bad) == [2, 3]
