"""Code audit (4 Nov 2026): a drafted `|re` with nested quantifiers backtracked for seconds on a 28-character
sample, so one bad draft could stall guard. Such a pattern is refused and the rule shows as not tested."""
import time

import pytest

from exception_guardian.guard.logtest import score_rule

RULE = """title: t
id: 5d6a8f4e-1b1a-4c55-9f0e-1a2b3c4d5e6f
status: experimental
logsource: {category: process_creation, product: linux}
detection:
  sel: {CommandLine|re: '%s'}
  condition: sel
tags: [cve.2025-54068]
"""
EVENTS = [{"_logsource": "process_creation/linux", "_label": "attack", "_attack": ["CVE-2025-54068"],
           "CommandLine": "a" * 28 + "!"},
          {"_logsource": "process_creation/linux", "_label": "benign", "CommandLine": "ls"}]


@pytest.mark.parametrize("pat", ["(a+)+$", "(a*)*b", "((ab)*)+c",
                                 "(a{1,5})+$"])
def test_nested_quantifiers_are_refused_fast(pat):
    t = time.monotonic()
    res = score_rule(RULE % pat, EVENTS, ("CVE-2025-54068",))
    assert time.monotonic() - t < 1
    assert res["tested"] is False and "nested quantifier" in res["reason"]


@pytest.mark.parametrize("pat", ["^a+!$", "curl .*\\| *sh", "(foo|bar)baz", "[a-z]{3}\\d+"])
def test_ordinary_patterns_still_run(pat):
    assert score_rule(RULE % pat, EVENTS, ("CVE-2025-54068",))["tested"] is True
