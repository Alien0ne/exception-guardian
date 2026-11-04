import json

from exception_guardian.config import SourceConfig
from exception_guardian.models import RuleType
from exception_guardian.readers import get_reader, read_all


def test_csv_reader_maps_types_and_skips_bad_row():
    ex, warn = read_all((SourceConfig("csv", {"path": "samples/csv/other_scanner_exceptions.csv", "map": "maps/other-scanner.yaml"}),))
    assert {e.rule_id for e in ex} == {"CSV-Q-201", "CSV-Q-202"}
    assert all(e.rule_type is RuleType.ACCEPT and e.source == "csv:other-scanner" for e in ex)
    assert any("row 4" in w for w in warn)


def test_csv_reader_accepts_json(tmp_path):
    rows = [{"Exception ID": "J1", "CVE": "CVE-2025-62593", "Host": "h", "Created On": "2026-01-05", "Expires On": "", "Reason": "x", "Approved By": "a", "State": "Active", "Exception Type": "Risk Accepted"}]
    p = tmp_path / "e.json"; p.write_text(json.dumps(rows))
    ex = get_reader("csv")({"path": str(p), "map": "maps/other-scanner.yaml"})
    assert ex[0].rule_id == "J1" and ex[0].expires is None


import pytest  # noqa: E402

GOOD_MAP = open("maps/other-scanner.yaml").read()
SAMPLE = "samples/csv/other_scanner_exceptions.csv"


def _read_with(tmp_path, map_text):
    m = tmp_path / "m.yaml"
    m.write_text(map_text)
    return get_reader("csv")({"path": SAMPLE, "map": str(m)})


@pytest.mark.parametrize("old,new,named", [
    ('  justification: "Reason"', '  justfication: "Reason"', "justfication"),   # typo: every row lost its reason
    ("columns:", "colums:", "colums"),                                           # no columns block at all
    ('"Active": enabled', '"Active": enabld', "enabld"),                          # status typo: a rule graded as live
    ('"Excluded": exclusion', '"Excluded": exclude', "exclude"),                  # type value that is no rule type
    ('date_format: "%Y-%m-%d"', 'date_fromat: "%Y-%m-%d"', "date_fromat"),       # silently the default format
])
def test_a_typo_in_the_map_stops_the_source_and_names_it(tmp_path, old, new, named):
    """Like guardian.yaml, a map with an unknown key or value must stop, never quietly fall back: a misspelled
    column key dropped every justification (false NO_JUSTIFICATION) and a misspelled status hid EXPIRED_STILL_ENABLED."""
    assert old in GOOD_MAP
    with pytest.raises(ValueError) as err:
        _read_with(tmp_path, GOOD_MAP.replace(old, new))
    assert named in str(err.value) and "m.yaml" in str(err.value)


def test_the_shipped_map_is_valid(tmp_path):
    assert {e.rule_id for e in _read_with(tmp_path, GOOD_MAP)} == {"CSV-Q-201", "CSV-Q-202"}
