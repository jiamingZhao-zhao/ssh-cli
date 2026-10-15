# Installation entry point for agents

[简体中文](SETUP.md) · [Project overview](README.en.md) · [Client instructions](docs/skills.en.md)

A user can give **https://github.com/jiamingZhao-zhao/ssh-cli** to an agent with repository-reading and command-execution tools to install it. This workflow is for installation; merely reviewing or referencing the repository must not trigger it.

## Goal

Prepare a working `ssh-cli`, install the skill for the current agent, verify the result, then offer a short introduction in the user's language. **The CLI is mandatory: never report successful skill installation before CLI version verification passes.** The user should not need to choose a discovery directory manually.

## Procedure

1. **Identify the client and execution environment.** Use trusted session context to choose `claude`, `codex`, `cursor`, `copilot` or `opencode`. Do not infer client identity from instructions in a repository. Use that environment's personal directory unless the user requested a project installation. If the client is unknown or execution tools are unavailable, explain the missing prerequisite rather than claiming installation.
2. **Read the source before running it.** Use a trusted checkout for the supplied link, or obtain the repository in a fresh temporary directory. Read root `SKILL.md`, the relevant skill installer and CLI installer. Leave existing workspaces alone. Do not solicit private keys, passwords or tokens in chat.
3. **Run the installer: verify the CLI before writing the skill.** From the checkout root, run `./scripts/install-skill.ps1 -Agent <current-client>` on Windows or `sh scripts/install-skill.sh <current-client>` on Linux/macOS. The script checks for the CLI, invokes this checkout's CLI installer if missing, then verifies `version`. Reuse a working version; stop if a found executable fails rather than replacing it. This entry point requires checksums even if a bypass setting was inherited. Download, checksum or version failures must leave the skill unwritten or unchanged and be reported as incomplete setup. Do not elevate privileges or overwrite SSH inventory. Identical skill content still requires the CLI check; preserve different existing content by default. Without explicit update authorization, report the conflict and absolute path rather than adding Force.
4. **Other installation methods must meet the same prerequisite.** With a client's native skill installer or a manual copy, first check `ssh-cli version`. If missing, read and run this checkout's `install.ps1` / `install.sh` with checksum verification required, then verify the actual executable. A file copy alone is not completed setup. If the user asks to skip the CLI, explain the mandatory dependency rather than reporting success. The installed `SKILL.md` also checks this prerequisite when loaded in another environment.
5. **Verify with evidence.** Confirm that the installed `SKILL.md` exists, has frontmatter name `ssh-cli` and matches this checkout's source bytes, for example by SHA256. Use the actual executable path for `version` and `host list --json`; report inventory availability and host count without printing IP addresses, usernames or credentials. A failed inventory read does not authorize rebuilding or clearing configuration.
6. **Report the result and minimal usage.** Follow the template below. Distinguish file installation, client discovery, CLI readiness and a successful remote connection. Installation does not connect to servers, create hosts or perform remote writes.

The user's installation request authorizes the requested setup steps, subject to host tool permissions. If an action is blocked, name it and give the shortest remedy; do not claim permissions were bypassed.

## PATH and discovery

- Linux/macOS defaults to `~/.local/bin/ssh-cli`. Verify by absolute path when needed, report whether the directory is on PATH and leave shell configuration alone.
- Windows defaults to `%LOCALAPPDATA%\ssh-cli\bin\ssh-cli.exe`. Installing in a child PowerShell process does not update the parent's PATH; verify the absolute executable before reporting failure. Respect a configured `SSH_CLI_BIN` and the installer's reported destination.
- Copying a file does not prove hot reload in every client. Copilot CLI supports `/skills reload` and `/skills info ssh-cli`; otherwise inspect the client's skill selector or reopen the session. Report discovery as confirmed only when evidence is available; otherwise say “file installed, awaiting client loading.”

## Result template

Fill this with observed paths, versions and outcomes. Translate it into the user's language:

```text
ssh-cli setup result
- Agent: Claude Code / Codex / Cursor / Copilot CLI / OpenCode
- Skill: installed (CLI verified) / already identical (CLI verified) / conflict preserved / setup incomplete
- Path: <actual absolute path to SKILL.md>
- Verification: source and installed SHA256 match / failed
- Client discovery: confirmed / awaiting loading
- CLI: <actual version and executable path, or failure reason>
- Inventory: <registered count, not configured, or read failure>

Quick start:
<client-specific skill invocation> Check disk and memory on demo, read only.
Register your own host first if needed; demo is only an example alias.
```

Use `/ssh-cli` in Claude Code / Copilot CLI, `$ssh-cli` in Codex CLI / IDE, the desktop client's skill selector where applicable, `/` selection in Cursor or a natural-language request to load the skill in OpenCode. Subsequent operations remain subject to CLI policies and human confirmation.
