#!/bin/sh
# install-skill.sh - copy the k8s-baseline-audit skill into an agent's skill folder.
#
# Skill folders, each verified against the vendor's own documentation on 2026-10-01.
# A skill is a directory containing SKILL.md (Agent Skills standard, https://agentskills.io/specification:
# name max 64 chars, lowercase a-z 0-9 and single hyphens, must match the directory name;
# description max 1024 chars).
#
#   agent    user level          project level     source
#   claude   ~/.claude/skills    .claude/skills    https://code.claude.com/docs/en/skills
#   cursor   ~/.cursor/skills    .cursor/skills    https://cursor.com/docs/skills
#   copilot  ~/.copilot/skills   .github/skills    https://docs.github.com/en/copilot/concepts/agents/about-agent-skills
#   codex    ~/.agents/skills    .agents/skills    https://developers.openai.com/codex/skills
#   gemini   ~/.gemini/skills    .gemini/skills    https://geminicli.com/docs/cli/skills/
#   agents   ~/.agents/skills    .agents/skills    generic location; also read by Codex, Gemini CLI,
#                                                  Cursor and Copilot per the pages above
#
# Never overwrites an existing install and never deletes anything.
set -eu

usage() {
  printf 'usage: %s AGENT [--project DIR]   agents: claude cursor copilot codex gemini agents\n' "$0" >&2
  exit 2
}

AGENT=${1:-}
[ -n "$AGENT" ] || usage
shift
PROJECT=""
while [ $# -gt 0 ]; do
  case $1 in
    --project) [ $# -ge 2 ] || usage; PROJECT=$2; shift 2 ;;
    *) usage ;;
  esac
done

SRC=$(cd "$(dirname "$0")/../skill/k8s-baseline-audit" && pwd)

if [ -n "$PROJECT" ]; then
  case $AGENT in
    claude) DEST="$PROJECT/.claude/skills" ;;
    cursor) DEST="$PROJECT/.cursor/skills" ;;
    copilot) DEST="$PROJECT/.github/skills" ;;
    gemini) DEST="$PROJECT/.gemini/skills" ;;
    agents|codex) DEST="$PROJECT/.agents/skills" ;;
    *) printf 'unknown agent: %s\n' "$AGENT" >&2; usage ;;
  esac
else
  case $AGENT in
    claude) DEST="$HOME/.claude/skills" ;;
    cursor) DEST="$HOME/.cursor/skills" ;;
    copilot) DEST="$HOME/.copilot/skills" ;;
    gemini) DEST="$HOME/.gemini/skills" ;;
    agents|codex) DEST="$HOME/.agents/skills" ;;
    *) printf 'unknown agent: %s\n' "$AGENT" >&2; usage ;;
  esac
fi

TARGET="$DEST/k8s-baseline-audit"
if [ -e "$TARGET" ]; then
  printf 'already installed at %s; remove it yourself to reinstall\n' "$TARGET" >&2
  exit 1
fi
mkdir -p "$DEST"
cp -R "$SRC" "$TARGET"
printf 'installed to %s\n' "$TARGET"
