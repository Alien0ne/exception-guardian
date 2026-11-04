"""Drive report.html in a real Chromium and print every scroll-spy or highlight mismatch (run by tests/test_html_scrollspy.py).

Usage: python3 scrollspy_check.py <report.html> <chromium path>. Needs Playwright; scroll events do not fire in
headless --dump-dom, so a real page is the only honest check.
"""
import pathlib
import sys

from playwright.sync_api import sync_playwright

SECTIONS = ("lead-h", "changes-h", "all-h", "hunt-h", "plan-h")
CURRENT = "document.querySelector('.sections a[aria-current]')?.hash || 'none'"
url, chromium = pathlib.Path(sys.argv[1]).resolve().as_uri(), sys.argv[2]
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=chromium, args=["--no-sandbox"])
    for width, height in ((1440, 1080), (1440, 900), (1440, 640), (390, 800)):
        page = browser.new_page(viewport={"width": width, "height": height})
        page.goto(url)
        for sid in ("changes-h", *SECTIONS, "changes-h"):          # each click starts where the last one left off
            try:
                page.click(f'.sections a[href="#{sid}"]', timeout=5000)
            except Exception:                                       # off-screen or covered: a user cannot tap it either
                print(f"{width}x{height} click {sid}: link cannot be reached")
                continue
            page.wait_for_timeout(1200)
            got = page.evaluate(CURRENT)
            if got != "#" + sid:
                print(f"{width}x{height} click {sid}: marked {got}")
        page.mouse.wheel(0, -10**6)
        page.wait_for_timeout(1200)
        if (got := page.evaluate(CURRENT)) != "none":
            print(f"{width}x{height} back at top: still marked {got}")
        # marked phrases replay: lit while in view, reset once fully out, lit again on return (either direction)
        lit = "document.querySelector('#plan-h .hl').classList.contains('is-active')"
        if page.evaluate(lit):
            print(f"{width}x{height} plan highlight still lit after leaving the screen")
        in_view = ("(() => { const r = document.querySelector('#plan-h .hl').getBoundingClientRect();"
                   " return r.top > 100 && r.bottom < innerHeight * 0.8; })()")
        for _ in range(400):                                        # wheel down until the phrase is well in view
            if page.evaluate(in_view):
                break
            page.mouse.wheel(0, 200)
            page.wait_for_timeout(30)
        page.wait_for_timeout(800)
        if not page.evaluate(lit):
            print(f"{width}x{height} plan highlight not lit after scrolling back down to it")
    browser.close()
print("done")
