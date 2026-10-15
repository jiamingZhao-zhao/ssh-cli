# Use ssh-cli with your AI agent

[简体中文](skills.md) · [Project homepage](../README.en.md) · [Skill source](../SKILL.md)

**Recommended: send https://github.com/jiamingZhao-zhao/ssh-cli to your agent.** The homepage routes installation requests to [SETUP.en.md](../SETUP.en.md): identify the client, install and verify the skill, check the CLI, then report paths, versions, inventory status and a usable example prompt. Manual instructions follow.

## Two separate pieces

**The CLI connects to servers; the skill teaches an agent how to call it.** This repository ships one standard `SKILL.md`. Discovery directories differ between hosts, but its instructions require no provider API, MCP server or provider-specific tool names.

Install the CLI and register hosts in the **environment where your agent actually executes commands**:

```sh
ssh-cli version
ssh-cli host list --json
```

A remote container, WSL session or cloud agent needs those prerequisites there, too. Installing the skill neither uploads local credentials nor grants permissions. A chat client without command execution cannot connect to your SSH servers just by loading these instructions.

## Install for your agent

Obtain the repository and run an installer from its root:

```sh
git clone https://github.com/jiamingZhao-zhao/ssh-cli.git
cd ssh-cli
```

Linux / macOS:

```sh
sh scripts/install-skill.sh claude
```

Windows PowerShell:

```powershell
.\scripts\install-skill.ps1 -Agent claude
```

Choices: `claude`, `codex`, `cursor`, `copilot`, `opencode`. The script only copies this checkout's `SKILL.md`; it does not install the CLI, change agent settings, loosen permissions or copy SSH configuration. Identical existing bytes are a successful no-op; different content causes an error. Review the old file before explicitly updating with `--force` / `-Force`.

| Agent | Personal directory | Project directory | Invocation / official docs |
| --- | --- | --- | --- |
| Claude Code | `~/.claude/skills/ssh-cli/` | `.claude/skills/ssh-cli/` | `/ssh-cli`; [Claude docs](https://code.claude.com/docs/en/skills) |
| Codex | `~/.agents/skills/ssh-cli/` | `.agents/skills/ssh-cli/` | `$ssh-cli` or `/skills` in CLI / IDE; [OpenAI docs](https://learn.chatgpt.com/docs/build-skills) |
| Cursor | `~/.cursor/skills/ssh-cli/` | `.cursor/skills/ssh-cli/` | Type `/` in Agent chat and select the skill; [Cursor docs](https://cursor.com/docs/skills) |
| GitHub Copilot CLI | `~/.copilot/skills/ssh-cli/` | `.github/skills/ssh-cli/` | `/ssh-cli`; [Copilot CLI docs](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills) |
| OpenCode | `~/.config/opencode/skills/ssh-cli/` | `.opencode/skills/ssh-cli/` | Ask the agent to load the `ssh-cli` skill; [OpenCode docs](https://opencode.ai/docs/skills) |

`~` is your user home directory, typically `C:\Users\your-name` on Windows. These paths describe the clients' local skill mechanisms. Versions, organization policies and cloud environments can affect discovery and execution; this is not a claim of live SSH testing in every client.

### Enable it for one project

Pass an existing project directory, not the eventual skill directory:

```sh
sh scripts/install-skill.sh claude --project /path/to/your-project
```

```powershell
.\scripts\install-skill.ps1 -Agent claude -Project 'D:\code\your-project'
```

Alternatively, create a directory from the table and copy the root `SKILL.md` into it. Avoid installing the same named skill in several directories that a single client scans.

## Start with a clear request

Claude Code / Copilot CLI:

```text
/ssh-cli Check disk and memory on demo. Read only; do not modify any files.
```

Codex CLI / IDE:

```text
$ssh-cli Check disk and memory on demo. Read only; do not modify any files.
```

Use the skill selector in the Codex desktop client; mention syntax depends on the client. In Cursor, select `ssh-cli` from the `/` menu. In OpenCode or another compatible agent, ask:

```text
Use the ssh-cli skill. List registered hosts, then check disk and memory on demo, read only.
```

Other concrete requests:

- “Inspect demo's recent audit records and explain failures. Do not replay commands.”
- “Check nginx status on demo. Report only; do not restart it.”
- “Upload local ./artifact.jar to /tmp/artifact.jar on demo. Leave any overwrite confirmation to me.”

The agent should resolve the alias first, inspect JSON outcomes, explain policy denials and verify remote state after a lost reply. **The skill does not replace policy checks, interactive TTY confirmation or OS permissions.**

## Update or remove

Update your checkout, then explicitly replace the installed skill:

```sh
sh scripts/install-skill.sh claude --force
```

```powershell
.\scripts\install-skill.ps1 -Agent claude -Force
```

For a project installation, pass the same project directory again. To uninstall, remove only the installed `ssh-cli` skill directory from the table; leave SSH inventory and credentials alone. CLI and skill updates are separate. Check `ssh-cli version` and subcommand `--help` before using a new flag.

## Troubleshooting

| Symptom | Next step |
| --- | --- |
| Skill not found | Check uppercase `SKILL.md`, parent directory `ssh-cli` and the client's discovery location; reopen the session, then restart the client if needed |
| Copilot CLI cannot see a newly added skill | Run `/skills reload`, then `/skills info ssh-cli` |
| Skill loads, command is missing | Check PATH and `ssh-cli version` inside the agent's execution environment |
| Registered hosts are missing | Check the execution user, `SSH_CLI_HOME` / `--config` and environment; do not paste credentials into chat |
| SSH agent authentication fails | Check `ssh-add -l` in that environment. A saved `agentKey` must match an available identity; do not clear it to bypass a failure |
| Policy denial / human confirmation required | Leave that confirmation to the user; do not edit policies, move environments or rewrap the command |
| Works locally, fails in the cloud | Personal skills, CLI, network access and credentials do not transfer automatically; local personal directories in Cursor or Claude do not establish a cloud installation |

Discovery paths and invocation methods were checked against the linked official documentation on **2026-10-15**. For agents without native skills, explicitly reading the file can supply task instructions; it does not create automatic discovery or SSH access.
