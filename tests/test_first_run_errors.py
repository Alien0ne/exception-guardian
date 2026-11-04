"""What a first-time user hits (fresh-user audit, 4 Nov 2026): a mistake must end in one line saying what to do,
never a traceback, and an input that reads nothing must never look like a clean run."""
from pathlib import Path

import pytest

from exception_guardian.cli import main
from exception_guardian.config import load_config
from exception_guardian.readers.csv_reader import read as read_csv

MAP = "maps/other-scanner.yaml"


def _err(capsys, argv):
    code = main(argv)
    err = capsys.readouterr().err
    assert "Traceback" not in err
    return code, err


def test_a_missing_config_is_one_line_naming_the_file(tmp_path, capsys):
    code, err = _err(capsys, ["find", "--config", "nope.yaml", "--out", str(tmp_path / "o")])
    assert code == 2 and err.startswith("error: ") and "nope.yaml" in err


def test_a_folder_that_is_not_a_run_says_run_find_first(tmp_path, capsys):
    for cmd in (["guard", "--run"], ["approve", "--run"], ["html", "--run"]):
        code, err = _err(capsys, cmd + [str(tmp_path / "missing")])
        assert code == 2 and "not a run folder" in err and "find" in err, cmd


def test_a_previous_run_that_does_not_exist_is_named(tmp_path, capsys):
    code, err = _err(capsys, ["find", "--config", "guardian.yaml", "--out", str(tmp_path / "o"), "--offline",
                              "--previous", str(tmp_path / "gone")])
    assert code == 2 and "gone" in err


def test_a_bad_date_is_explained(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        main(["find", "--out", str(tmp_path / "o"), "--today", "notadate"])
    assert e.value.code == 2 and "YYYY-MM-DD" in capsys.readouterr().err


def test_broken_yaml_is_one_line(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("sources: [\n  - name: csv\n")
    code, err = _err(capsys, ["find", "--config", str(bad), "--out", str(tmp_path / "o")])
    assert code == 2 and "bad.yaml" in err


def test_a_misspelt_config_key_is_refused(tmp_path):
    p = tmp_path / "g.yaml"
    p.write_text("sorces: []\n")
    with pytest.raises(ValueError, match=r"sorces.*sources"):
        load_config(p)


def test_an_empty_source_list_is_refused(tmp_path):
    p = tmp_path / "g.yaml"
    p.write_text("sources: []\n")
    with pytest.raises(ValueError, match="no sources"):
        load_config(p)


def test_a_bad_value_names_its_key(tmp_path):
    p = tmp_path / "g.yaml"
    p.write_text("revoke_epss: high\n")
    with pytest.raises(ValueError, match="revoke_epss"):
        load_config(p)


def test_a_csv_without_the_mapped_columns_fails_and_says_what_it_has(tmp_path):
    f = tmp_path / "other.csv"
    f.write_text("Plugin,Asset,Date\n1,h1,2026-01-01\n")
    with pytest.raises(ValueError, match=r"Exception Type.*it has: Plugin, Asset, Date"):
        read_csv({"path": str(f), "map": MAP})


@pytest.mark.parametrize("text", ["", "Exception ID,CVE,Host,Created On,Expires On,Reason,Approved By,State,"
                                      "Exception Type\n"])
def test_a_csv_with_no_rows_fails(tmp_path, text):
    f = tmp_path / "empty.csv"
    f.write_text(text)
    with pytest.raises(ValueError, match="no rows"):
        read_csv({"path": str(f), "map": MAP})


def test_a_wrong_csv_makes_a_partial_run_not_a_clean_one(tmp_path, capsys):
    f = tmp_path / "other.csv"
    f.write_text("Plugin,Asset,Date\n1,h1,2026-01-01\n")
    cfg = tmp_path / "g.yaml"
    cfg.write_text(f"sources:\n  - name: csv\n    path: {f}\n    map: {Path(MAP).resolve()}\n")
    code, err = _err(capsys, ["find", "--config", str(cfg), "--out", str(tmp_path / "o"), "--offline"])
    assert code == 3 and "PARTIAL RUN" in err


def test_skipped_rows_are_counted_on_the_terminal(tmp_path, capsys):
    f = tmp_path / "x.csv"
    f.write_text("Exception ID,CVE,Host,Created On,Expires On,Reason,Approved By,State,Exception Type\n"
                 "A,CVE-2025-1,h,2026-01-01,,r,o,Active,Risk Accepted\n"
                 "B,CVE-2025-62593,h,01/02/2026,,r,o,Active,Risk Accepted\n"
                 "C,CVE-2025-62593,h,2026-01-01,,r,o,Active,Risk Accepted\n")
    cfg = tmp_path / "g.yaml"
    cfg.write_text(f"sources:\n  - name: csv\n    path: {f}\n    map: {Path(MAP).resolve()}\n")
    main(["find", "--config", str(cfg), "--out", str(tmp_path / "o"), "--offline"])
    assert "warning: 2 rows skipped (see Warnings in report.md)" in capsys.readouterr().err


def test_ticket_text_names_the_run_folder_not_a_home_path(tmp_path):
    run = tmp_path / "deep" / "out" / "demo"
    assert main(["demo", "--out", str(run)]) == 0
    plan = (run / "approval-plan.md").read_text()
    assert str(tmp_path) not in plan and "demo" in plan


def test_missing_tenable_keys_are_one_line_not_a_traceback(tmp_path, monkeypatch, capsys):
    """Review of src, 4 Nov 2026: `dcs` on a live run with no keys set ended in a RuntimeError traceback."""
    import json as _json
    cfg = tmp_path / "live.yaml"
    cfg.write_text("sources:\n  - name: tenable-vm\n    base_url: https://example.invalid\n")
    run = tmp_path / "run"
    run.mkdir()
    (run / "findings.json").write_text(_json.dumps({"today": "2026-11-04", "findings": [], "config": str(cfg)}))
    for v in ("TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("EG_ENV_FILE", str(tmp_path / "no.env"))
    monkeypatch.delenv("EG_DEBUG", raising=False)
    assert main(["dcs", "--run", str(run)]) == 2
    err = capsys.readouterr().err
    assert "error: environment variable TENABLE_ACCESS_KEY is not set" in err and "Traceback" not in err


def test_a_missing_exposure_claims_file_is_a_usage_error(tmp_path, capsys):
    assert main(["find", "--out", str(tmp_path / "o"), "--exposure-claims", str(tmp_path / "none.json")]) == 2
    assert "--exposure-claims" in capsys.readouterr().err
