"""Fresh-user audit (4 Nov 2026), at 390px: the section menu hid Hunt queries and Plan off-screen (a sideways
scroller with no scrollbar), and trigger names such as JUSTIFICATION_CONTRADICTED split mid-word. Measured in a
browser by hand; these pin the markup and the rule that fix it."""
import re
from pathlib import Path

from exception_guardian.cli import main

CSS = Path("src/exception_guardian/templates/report.css").read_text()


def test_trigger_names_break_only_after_an_underscore(tmp_path):
    run = tmp_path / "demo"
    assert main(["demo", "--out", str(run)]) == 0
    page = (run / "report.html").read_text()
    assert '<code class="trig">JUSTIFICATION_<wbr>CONTRADICTED</code>' in page
    assert re.search(r"code\.trig \{[^}]*overflow-wrap: normal", CSS)


def test_the_section_menu_wraps_on_small_screens_instead_of_hiding_links():
    small = CSS[CSS.index("@media (width <= 992px) {\n  .topbar .container"):]
    small = small[:small.index("\n}") + 2]
    assert "flex-wrap: wrap" in small and "overflow-x: auto" not in small


def test_a_stacked_cell_keeps_its_content_in_one_flow():
    """A grid cell made each piece its own item: 'Review to Revoke' split, and 'to' sat in the label column."""
    small = CSS[CSS.index("@media (width <= 768px) {\n  :root { --card-pad"):]
    small = small[:small.index("\n}") + 2]
    td = re.search(r"\n  table\.stack td \{([^}]*)\}", small).group(1)
    assert "display: grid" not in td and "calc(7rem" in td
    assert re.search(r"table\.stack td::before \{[^}]*position: absolute", small)
