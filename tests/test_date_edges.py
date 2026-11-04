"""Code audit (4 Nov 2026): Security Center sends expires 0 for "never", which read as 1 Jan 1970 (so an
open-ended rule looked long expired), and the VM reader read the basic ISO date 20240101 as epoch seconds."""
from datetime import date

import pytest

from exception_guardian.readers.tenable_sc import _epoch
from exception_guardian.readers.tenable_vm import _iso_date


@pytest.mark.parametrize("v", [0, "0", "0.0", -1, "-1", -5, None, ""])
def test_sc_zero_or_negative_expiry_means_never(v):
    assert _epoch(v) is None


def test_sc_real_epoch_still_reads():
    assert _epoch("1767225600") == date(2026, 1, 1)


@pytest.mark.parametrize("v", ["20240101", 20240101])
def test_basic_iso_date_is_a_date_not_epoch_seconds(v):
    assert _iso_date(v) == date(2024, 1, 1)


@pytest.mark.parametrize("v,want", [(1767225600, date(2026, 1, 1)), (1767225600000, date(2026, 1, 1)),
                                    ("2026-01-01T05:00:00Z", date(2026, 1, 1)), (0, None)])
def test_other_forms_unchanged(v, want):
    assert _iso_date(v) == want
