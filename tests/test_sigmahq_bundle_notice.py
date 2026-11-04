"""The bundled SigmaHQ rules can be rebuilt by a stranger: the notice names both steps, and the index, the notice
and every bundled rule's source link are at one pinned commit."""
import json
import re
from pathlib import Path

DATA = Path("src/exception_guardian/data")


def test_notice_names_both_rebuild_steps_in_order():
    notice = (DATA / "sigmahq" / "NOTICE.md").read_text()
    script = Path("scripts/bundle_sigmahq.py").read_text()
    for text in (notice, script):
        i, b = text.find("scripts/build_sigmahq_index.py"), text.find("then `scripts/bundle_sigmahq.py`")
        assert 0 <= i < b, "the notice must say: build the index, then bundle"


def test_index_notice_and_rules_share_one_commit():
    commit = json.loads((DATA / "sigmahq_index.json").read_text())["commit"]
    notice = (DATA / "sigmahq" / "NOTICE.md").read_text()
    assert f"at commit `{commit}`" in notice
    assert set(re.findall(r"SigmaHQ/sigma/blob/([0-9a-f]{40})/", notice)) == {commit}
