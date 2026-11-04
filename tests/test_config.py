import pytest

from exception_guardian.config import load_config
from exception_guardian.models import Grade


def test_defaults_when_file_minimal(tmp_path):
    p = tmp_path / "g.yaml"; p.write_text("")
    c = load_config(p)
    assert (c.revoke_epss, c.review_max_age_days, c.review_epss_delta) == (0.5, 365, 0.1)
    assert c.siem_targets == ("splunk", "sentinel", "defender")


def test_sources_parsed(tmp_path):
    p = tmp_path / "g.yaml"
    p.write_text("sources:\n  - name: csv\n    path: x.csv\n    map: maps/m.yaml\n")
    c = load_config(p)
    assert c.sources[0].name == "csv" and c.sources[0].params["path"] == "x.csv"


def test_unknown_siem_target_rejected(tmp_path):
    p = tmp_path / "g.yaml"; p.write_text("siem_targets: [qradar]\n")
    with pytest.raises(ValueError):
        load_config(p)


def test_grade_rank():
    assert Grade.REVOKE.rank > Grade.REVIEW.rank > Grade.OK.rank


# Review of src, 4 Nov 2026: a list key written as one string was split into letters, so
# `internal_keywords: internal` matched almost any justification and `internet_tags: Exposure:Internet` matched no tag.
@pytest.mark.parametrize("text,get,want", [
    ("internal_keywords: Internal\n", lambda c: c.internal_keywords, ("internal",)),
    ("siem_targets: splunk\n", lambda c: c.siem_targets, ("splunk",)),
    ("exposure:\n  internet_tags: Exposure:Internet\n", lambda c: c.exposure.internet_tags, ("Exposure:Internet",)),
    ("exposure:\n  internet_ranges: 198.51.100.0/24\n", lambda c: c.exposure.internet_ranges, ("198.51.100.0/24",)),
])
def test_a_list_key_given_one_string_is_one_item(tmp_path, text, get, want):
    p = tmp_path / "g.yaml"
    p.write_text(text)
    assert get(load_config(p)) == want


@pytest.mark.parametrize("text,says", [
    ("sources:\n  - type: csv\n", "sources: entry 1 has no name"),
    ("sources: tenable-vm\n", "sources: give a list"),
    ("sources:\n  - tenable-vm\n", "sources: entry 1 is not a map"),
    ("assets: [a]\n", "assets: give a map"),
    ("exposure: [Exposure:Internet]\n", "exposure: give a map"),
    ("internal_keywords: {a: 1}\n", "internal_keywords: give a list"),
])
def test_a_wrong_shape_names_the_key(tmp_path, text, says):
    p = tmp_path / "g.yaml"
    p.write_text(text)
    with pytest.raises(ValueError, match=says):
        load_config(p)
