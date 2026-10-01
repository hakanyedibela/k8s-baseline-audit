import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from k8s_baseline_audit.report.render import Narrative, validate_narratives

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill" / "k8s-baseline-audit" / "SKILL.md"
INSTALL = ROOT / "scripts" / "install-skill.sh"
AGENT_SPECIFIC = (
    "mcp__", "Bash tool", "Read tool", "Write tool", "Skill tool", "TodoWrite", "AskUserQuestion",
)
EXAMPLE_FINDING_ID = "0123456789abcdef"


def _split():
    text = SKILL.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    assert m, "SKILL.md must start with YAML frontmatter"
    return yaml.safe_load(m.group(1)), m.group(2)


def test_frontmatter_follows_agent_skills_standard():
    front, _ = _split()
    assert set(front) == {"name", "description"}
    assert front["name"] == SKILL.parent.name
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", front["name"]) and len(front["name"]) <= 64
    assert 0 < len(front["description"]) <= 1024


def test_body_is_agent_neutral_and_uses_real_commands():
    _, body = _split()
    for token in AGENT_SPECIFIC:
        assert token not in body, token
    for cmd in (
        "k8s-baseline-audit collect", "k8s-baseline-audit analyze", "k8s-baseline-audit report",
    ):
        assert cmd in body, cmd
    rules, _, steps = body.partition("## Step 0")
    assert steps, "SKILL.md needs a '## Step 0' section after the hard rules"
    for forbidden in ("kubectl apply", "kubectl delete", "kubectl patch", "kubectl exec"):
        assert forbidden in rules  # named in the prohibition list
        assert forbidden not in steps  # never used in an instruction


def test_narrative_examples_validate():
    _, body = _split()
    blocks = re.findall(r"```json\n(.*?)\n```", body, re.S)
    assert len(blocks) >= 2
    narratives = {}
    for block in blocks:
        n = Narrative.model_validate(json.loads(block))
        narratives[n.language] = n
    assert set(narratives) == {"de", "en"}
    # passes the renderer's own checks (forbidden words, markdown syntax, de/en parity)
    validate_narratives(narratives, {EXAMPLE_FINDING_ID})


def test_narrative_rules_are_stated():
    _, body = _split()
    for token in ("erfüllt", "fulfilled", "compliant", "konform", "duplicate", "NarrativeError"):
        assert token in body, token


def _install(agent, home, *extra):
    return subprocess.run(
        ["sh", str(INSTALL), agent, *extra],
        env={**os.environ, "HOME": str(home)},
        capture_output=True, text=True, check=False,
    )


@pytest.mark.parametrize(
    "agent,rel",
    [
        ("claude", ".claude/skills"),
        ("copilot", ".copilot/skills"),
        ("cursor", ".cursor/skills"),
        ("agents", ".agents/skills"),
        ("codex", ".agents/skills"),
        ("gemini", ".gemini/skills"),
    ],
)
def test_user_level_install(tmp_path, agent, rel):
    proc = _install(agent, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / rel / "k8s-baseline-audit" / "SKILL.md").is_file()


@pytest.mark.parametrize(
    "agent,rel",
    [
        ("claude", ".claude/skills"),
        ("cursor", ".cursor/skills"),
        ("copilot", ".github/skills"),
        ("agents", ".agents/skills"),
        ("codex", ".agents/skills"),
        ("gemini", ".gemini/skills"),
    ],
)
def test_project_level_install(tmp_path, agent, rel):
    proj = tmp_path / "proj"
    proj.mkdir()
    proc = _install(agent, tmp_path, "--project", str(proj))
    assert proc.returncode == 0, proc.stderr
    assert (proj / rel / "k8s-baseline-audit" / "SKILL.md").is_file()


def test_existing_install_is_not_overwritten(tmp_path):
    assert _install("claude", tmp_path).returncode == 0
    marker = tmp_path / ".claude/skills/k8s-baseline-audit/SKILL.md"
    marker.write_text("local edit", encoding="utf-8")
    second = _install("claude", tmp_path)
    assert second.returncode == 1
    assert "already installed" in second.stderr
    assert marker.read_text(encoding="utf-8") == "local edit"


def test_usage_errors(tmp_path):
    assert _install("bolt", tmp_path).returncode == 2
    assert _install("claude", tmp_path, "--project").returncode == 2
    assert _install("claude", tmp_path, "--bogus").returncode == 2
    assert _install("", tmp_path).returncode == 2
