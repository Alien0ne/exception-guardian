"""Code audit (4 Nov 2026): an exception on "prod-*" matched no asset, so its covered assets, their exposure and
criticality never reached the grade. Wildcards in names and tag values now match like the source means them."""
from exception_guardian.assets import match, parse_assets

ASSETS = parse_assets([
    {"id": "a1", "hostname": ["prod-web1"], "fqdn": ["prod-web1.corp.example"], "ipv4": ["10.0.0.1"],
     "tags": [{"tag_key": "Env", "tag_value": "prod-eu"}]},
    {"id": "a2", "hostname": ["dev-web1"], "ipv4": ["10.0.0.2"], "tags": [{"tag_key": "Env", "tag_value": "dev"}]},
])


def _ids(targets):
    return [a.id for a in match(targets, ASSETS)]


def test_a_name_wildcard_matches():
    assert _ids(("prod-*",)) == ["a1"]
    assert _ids(("*.corp.example",)) == ["a1"]


def test_a_tag_value_wildcard_matches():
    assert _ids(("tag:env:prod*",)) == ["a1"]


def test_an_excluded_wildcard_excludes():
    assert _ids(("!prod-*",)) == ["a2"]


def test_a_lone_star_is_still_every_asset_and_plain_names_are_exact():
    assert _ids(("*",)) == ["a1", "a2"] and _ids(("prod",)) == []
