import os
from pathlib import Path

# Tests run from the repo root so relative sample paths resolve.
os.chdir(Path(__file__).resolve().parent.parent)

from dataclasses import replace  # noqa: E402
from datetime import date  # noqa: E402

import pytest  # noqa: E402

TODAY = date(2026, 11, 2)


def _inputs():
    from exception_guardian.assets import load_assets
    from exception_guardian.config import load_config
    from exception_guardian.intel import build_intel
    from exception_guardian.readers import read_all
    cfg = replace(load_config("guardian.yaml"), offline=True)
    exceptions, _ = read_all(cfg.sources)
    from exception_guardian.exposure import apply_exposure
    assets, _ = apply_exposure(load_assets(cfg.assets), cfg.exposure)  # as run_find does
    wanted: dict = {}
    for e in exceptions:
        for c in e.cves:
            wanted.setdefault(c, []).append(e.created)
    intel, _ = build_intel(wanted, cfg)
    return cfg, exceptions, assets, intel


@pytest.fixture(scope="session")
def graded():
    from exception_guardian.grading import grade
    cfg, exceptions, assets, intel = _inputs()
    return {e.rule_id: grade(e, assets, intel, cfg, TODAY) for e in exceptions}


@pytest.fixture(scope="session")
def hero_inputs():
    _, exceptions, assets, intel = _inputs()
    return next(e for e in exceptions if e.rule_id == "R-HERO-001"), assets, intel


@pytest.fixture(autouse=True)
def _not_an_agent_shell(monkeypatch):
    """Tests may run inside a Claude Code shell or a harness run. The CLI refuses --apply there, so clear the
    markers: tests that need them set them again."""
    for var in ("CLAUDECODE", "EG_HARNESS", "EG_ENV_FILE"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _own_intel_cache(monkeypatch, tmp_path_factory):
    """The EPSS history cache defaults to the person's cache folder: each test gets an empty one of its own."""
    monkeypatch.setenv("EG_CACHE_DIR", str(tmp_path_factory.mktemp("eg-cache")))


@pytest.fixture(autouse=True)
def _no_live_exploit_feeds(monkeypatch):
    """No test downloads the public exploit feeds (three files, 24 MB): a test that wants them passes its own fetch."""
    import exception_guardian.exploits as exploits
    calls = []
    monkeypatch.setattr(exploits, "_http_text", lambda url: calls.append(url) or (_ for _ in ()).throw(
        ConnectionError("tests do not fetch exploit feeds")))
    yield
    if calls and os.environ.get("EG_SHOW_FEED_CALLS"):
        print(f"\nFEED-CALLS {len(calls)}")
