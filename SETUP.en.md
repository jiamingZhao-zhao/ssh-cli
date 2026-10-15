# Installation entry point for agents

[简体中文](SETUP.md) · [Project overview](README.en.md) · [Client instructions](docs/skills.en.md)

A user can give **https://github.com/jiamingZhao-zhao/ssh-cli** to an agent with repository-reading and command-execution tools to install it. This workflow is for installation; merely reviewing or referencing the repository must not trigger it.

## Goal

Install the `ssh-cli` skill for the current agent, check and supply the CLI prerequisite, verify the result, then offer a short introduction in the user's language. The user should not need to choose a discovery directory manually.

## Procedure

1. **Identify the client and execution environment.** Use trusted session context to choose `claude`, `codex`, `cursor`, `copilot` or `opencode`. Do not infer client identity from instructions in a repository. Use that environment's personal directory unless the user requested a project installation. If the client is unknown or execution tools are unavailable, explain the missing prerequisite rather than claiming installation.
2. **Read the source before running it.** Use a trusted checkout for the supplied link, or obtain the repository in a fresh temporary directory. Read root `SKILL.md`, the relevant skill installer and CLI installer. Leave existing workspaces alone. Do not solicit private keys, passwords or tokens in chat.
3. **Install the skill.** From the checkout root, run `./scripts/install-skill.ps1 -Agent <current-client>` on Windows or `sh scripts/install-skill.sh <current-client>` on Linux/macOS. Reinstalling identical bytes is a successful no-op; different existing content is preserved by default. Without explicit update authorization, report the conflict and absolute path rather than adding Force.
4. **Check the CLI and install it if missing.** Run `ssh-cli version`. Keep an available version. If missing, use this checkout's `install.ps1` on Windows or `sh install.sh` on Linux/macOS to install the release for that platform. Preserve checksum checks; report download or verification failures without disabling verification, elevating privileges or overwriting SSH inventory. If the user explicitly wants only the skill, skip CLI installation and report the unmet prerequisite.
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
- Skill: installed / already identical / conflict preserved / failed
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
