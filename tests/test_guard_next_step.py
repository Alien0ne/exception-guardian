"""Fresh-user audit (4 Nov 2026): guard listed missing drafts and stopped, with no word on what to do next."""
from exception_guardian.cli import main


def _run(tmp_path):
    run = tmp_path / "demo"
    assert main(["demo", "--out", str(run)]) == 0
    return run


def test_missing_drafts_come_with_the_next_step(tmp_path, capsys):
    run = _run(tmp_path)
    for f in (run / "drafts").glob("*.yml"):
        f.unlink()
    capsys.readouterr()
    assert main(["guard", "--run", str(run), "--config", "guardian.yaml"]) == 0
    out = capsys.readouterr().out
    assert "next: draft a Sigma rule for each missing CVE" in out
    assert str(run / "drafts") in out and "/eg-guard" in out


def test_a_complete_guard_points_at_approve(tmp_path, capsys):
    run = _run(tmp_path)
    capsys.readouterr()
    assert main(["guard", "--run", str(run), "--config", "guardian.yaml"]) == 0
    out = capsys.readouterr().out
    assert f"next: exception-guardian approve --run {run}" in out
