#!/bin/sh
# Ensure the CLI works before installing the canonical SKILL.md.
set -eu

usage() {
  echo 'Usage: sh scripts/install-skill.sh <claude|codex|cursor|copilot|opencode> [--project DIRECTORY] [--force]'
}
[ "$#" -gt 0 ] || { usage >&2; exit 2; }
case "$1" in -h|--help) usage; exit 0;; esac
agent=$1
shift
project=
force=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --project) [ "$#" -ge 2 ] && [ -n "$2" ] || { usage >&2; exit 2; }; project=$2; shift 2;;
    --force) force=true; shift;;
    *) usage >&2; exit 2;;
  esac
done
case "$agent" in
  claude) user_dir=.claude/skills; project_dir=.claude/skills;;
  codex) user_dir=.agents/skills; project_dir=.agents/skills;;
  cursor) user_dir=.cursor/skills; project_dir=.cursor/skills;;
  copilot) user_dir=.copilot/skills; project_dir=.github/skills;;
  opencode) user_dir=.config/opencode/skills; project_dir=.opencode/skills;;
  *) usage >&2; exit 2;;
esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -n "$project" ]; then
  [ -d "$project" ] || { echo 'Project directory does not exist.' >&2; exit 2; }
  project=$(CDPATH= cd -- "$project" && pwd)
  destination=$project/$project_dir/ssh-cli
else
  [ -n "${HOME:-}" ] || { echo 'HOME is unavailable; use --project DIRECTORY.' >&2; exit 2; }
  destination=$HOME/$user_dir/ssh-cli
fi
target=$destination/SKILL.md
identical=false
[ ! -L "$target" ] || { echo 'Refusing to replace a symbolic link.' >&2; exit 1; }
if [ -e "$target" ] && [ "$force" != true ]; then
  if cmp -s "$root/SKILL.md" "$target"; then
    identical=true
  else
    echo "Already exists: $target. Review it, then use --force to update." >&2
    exit 1
  fi
fi
cli=${SSH_CLI_BIN:-${HOME:?HOME is required}/.local/bin}/ssh-cli
if [ ! -e "$cli" ]; then
  if command -v ssh-cli >/dev/null 2>&1; then
    cli=$(command -v ssh-cli)
  else
    SSH_CLI_ALLOW_MISSING_CHECKSUM=0 sh "$root/install.sh"
  fi
fi
if [ ! -x "$cli" ] || ! cli_version=$("$cli" version) || [ -z "$cli_version" ]; then
  echo 'ssh-cli version failed; Skill was not installed. Repair the CLI before retrying.' >&2
  exit 1
fi
printf 'CLI ready: %s (%s)\n' "$cli" "$cli_version"
if [ "$identical" = true ]; then
  printf 'ssh-cli skill already installed for %s:\n%s\n' "$agent" "$target"
  exit 0
fi
mkdir -p -- "$destination"
cp -- "$root/SKILL.md" "$target"
printf 'Installed ssh-cli skill for %s:\n%s\n' "$agent" "$target"
echo 'CLI verified. Configure hosts separately before remote operations.'
