from datetime import date

from exception_guardian.assets import load_assets, match


def test_internet_facing_from_tag_and_match_by_fqdn():
    from exception_guardian.config import ExposureConfig
    from exception_guardian.exposure import apply_exposure
    a, _ = apply_exposure(load_assets({"fixture": "samples/tenable_vm/assets.json"}),
                          ExposureConfig(internet_tags=("Exposure:Internet",)))
    web = match(("web-portal-01.example.com",), a)
    assert web and web[0].internet_facing and web[0].exposure_since == date(2026, 10, 28)


def test_match_by_name_ip_case_insensitive_and_internal():
    a = load_assets({"fixture": "samples/tenable_vm/assets.json"})
    assert match(("FTP-01",), a)[0].critical is True
    hr = match(("192.0.2.42",), a)
    assert hr[0].name == "hr-app-02" and not hr[0].internet_facing
    assert match(("unknown-host-99.example.com",), a) == []
