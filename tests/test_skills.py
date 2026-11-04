import re
from pathlib import Path

import yaml

SKILLS = ("SKILL.md", "skills/exception-guardian-find/SKILL.md", "skills/exception-guardian-guard/SKILL.md")


def test_skill_files_have_frontmatter_and_refs_exist():
    for p in SKILLS:
        fm = yaml.safe_load(Path(p).read_text().split("---")[1])
        assert fm["name"] and fm["description"]
    for ref in re.findall(r"`((?:skills|samples|maps|templates|src|references)/[^`]+)`", Path("SKILL.md").read_text()):
        assert Path(ref).exists(), ref


def test_playbook_names_and_untrusted_data_rules():
    names = [yaml.safe_load(Path(p).read_text().split("---")[1])["name"] for p in SKILLS]
    assert names == ["exception-guardian", "exception-guardian-find", "exception-guardian-guard"]
    body = Path("SKILL.md").read_text()
    assert "## Untrusted data" in body and "never change a grade" in body.lower()
    assert "--apply" in body and "explicitly" in body


def test_guard_skill_forbids_exploit_content():
    body = Path("skills/exception-guardian-guard/SKILL.md").read_text().lower()
    assert "detection only" in body and "status: experimental" in body and "references" in body


REFS = ("references/commands.md", "references/grades.md", "references/worked-example.md", "references/troubleshooting.md")


def test_skill_points_to_every_reference_page():
    body = Path("SKILL.md").read_text()
    for ref in REFS:
        assert f"`{ref}`" in body and Path(ref).read_text().startswith("# "), ref


def test_every_trigger_the_grader_can_emit_is_documented():
    import exception_guardian.grading as grading
    emitted = set(re.findall(r'Trigger\("([A-Z_]+)"', Path(grading.__file__).read_text()))
    documented = set(re.findall(r"^\| `([A-Z_]+)` \|", Path("references/grades.md").read_text(), re.M))
    assert emitted and emitted == documented, (emitted - documented, documented - emitted)


def test_every_cli_command_and_flag_is_documented():
    from exception_guardian.cli import build_parser
    doc = Path("references/commands.md").read_text()
    sub = next(a for a in build_parser()._actions if a.dest == "cmd")
    for name, parser in sub.choices.items():
        assert f"### `{name}`" in doc, name
        for act in parser._actions:
            for flag in act.option_strings:
                if flag.startswith("--") and flag != "--help":
                    assert f"`{flag}" in doc, f"{name} {flag}"


def test_slash_command_runs_the_playbook():
    cmd = Path(".claude/commands/exception-guardian.md").read_text()
    fm = yaml.safe_load(cmd.split("---")[1])
    assert fm["description"] and "SKILL.md" in cmd and "--apply" in cmd


def test_ci_runs_tests_and_secret_scan():
    ci = Path(".github/workflows/ci.yml").read_text()
    assert "pytest" in ci and "gitleaks" in ci and "permissions:" in ci


def test_readme_workflow_diagram_and_stage_table_follow_the_skill_steps():
    steps = re.findall(r"^## Step \d: (\w+)", Path("SKILL.md").read_text(), re.M)
    readme = Path("README.md").read_text()
    section = readme.split("## How it works", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| \*\*\d\. (\w+)\*\* \|", section, re.M)
    assert steps == ["Find", "Guard", "Approve", "Hunt"] and rows == steps
    for f in ("workflow.png", "workflow.webp", "workflow-eric.mp4", "workflow-alice.mp4"):
        assert f"(docs/media/{f})" in section and (Path("docs/media") / f).is_file(), f
    alt = re.search(r"!\[([^\]]*)\]\(docs/media/workflow\.png\)", section).group(1)
    names = ["Find", "1b Exposure", "1c DCs", "Guard", "Approve", "Hunt"]
    assert [alt.index(n) for n in names] == sorted(alt.index(n) for n in names)   # the diagram's text, in order
    assert "Human checkpoint" in section.split("| Step |", 1)[1]


def test_skills_never_send_claude_to_the_key_variables():
    """Live run, 4 Nov 2026: the find skill said "set the keys as environment variables", and Claude checked
    TENABLE_ACCESS_KEY and the rest in its own shell. The keys live in .env (or EG_ENV_FILE) and only the CLI reads
    them, so no skill may point Claude at the environment for them."""
    for f in SKILLS:
        body = " ".join(Path(f).read_text().split())
        assert "keys as environment variables" not in body, f
        assert "come only from environment variables" not in body, f


def test_skill_limitations_match_the_live_apply_run():
    body = " ".join(Path("SKILL.md").read_text().split())
    assert "tested on the local mock only" not in body


def test_eg_find_offers_exposure_only_on_the_warning_like_the_skill():
    """find writes exposure-candidates.json on every run, so it cannot be the trigger for Step 1b: SKILL.md and
    /eg-run offer the step only when find warns that no asset is marked internet-facing."""
    body = " ".join(Path(".claude/commands/eg-find.md").read_text().split())
    assert "lists assets, offer Step 1b" not in body
    assert "no asset is marked internet-facing" in body
