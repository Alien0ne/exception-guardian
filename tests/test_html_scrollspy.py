import shutil
import subprocess
from pathlib import Path

import pytest

from exception_guardian.cli import main

CHECK = Path(__file__).parent / "browser" / "scrollspy_check.py"
CHROMIUM = shutil.which("chromium") or shutil.which("chromium-browser")
PLAYWRIGHT = subprocess.run(["python3", "-c", "import playwright"], capture_output=True).returncode == 0 \
    if shutil.which("python3") else False


@pytest.mark.skipif(not (CHROMIUM and PLAYWRIGHT), reason="needs chromium and Playwright for system python3")
def test_section_links_mark_the_section_clicked_at_every_size(tmp_path):
    assert main(["demo", "--out", str(tmp_path)]) == 0
    out = subprocess.run(["python3", str(CHECK), str(tmp_path / "report.html"), CHROMIUM],
                         capture_output=True, text=True, timeout=240)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip() == "done", out.stdout
