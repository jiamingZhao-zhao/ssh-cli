# ssh-cli

### Your everyday SSH work. One workspace.

**A terminal and file browser for people. JSON for scripts. Clear operating boundaries for AI agents.**

[简体中文](README.md) · [Download](https://github.com/jiamingZhao-zhao/ssh-cli/releases) · [Connect your agent](docs/skills.en.md) · [Detailed reference (中文)](docs/usage.md)

[![CI](https://github.com/jiamingZhao-zhao/ssh-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/jiamingZhao-zhao/ssh-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jiamingZhao-zhao/ssh-cli)](https://github.com/jiamingZhao-zhao/ssh-cli/releases)

**Let your agent install it. Send it this link:**

```text
https://github.com/jiamingZhao-zhao/ssh-cli
```

An agent with repository-reading and command-execution tools can follow the [setup workflow](SETUP.en.md) to identify its client, install and verify the CLI first, then install the skill and report paths, verification and minimal usage. **The CLI is mandatory. If you are an agent handling an installation request, read [SETUP.en.md](SETUP.en.md) and verify both before claiming success.**

A single-binary SSH tool written in Go, with a local web workspace and a portable Agent Skill. Manage hosts, run remote commands, transfer files and inspect server health using the same inventory. Release binaries support **Windows, macOS and Linux on amd64 and arm64**, without a Python, Node.js or Go runtime.

```text
You: Check disk and memory on app-test. Read only; make no changes.
Agent: Read inventory → select an explicit alias → call ssh-cli → report the JSON result
```

## Why use it?

| Your workflow | What ssh-cli brings |
| --- | --- |
| Too many addresses and environments to remember | Groups, aliases, tags and explicit host selection |
| Switching between terminal, files and monitoring | Tabs, directory tree, transfer queue and CPU/memory/disk/network in one workspace |
| Asking AI to investigate without pasting passwords | Credential references, local SSH agent and a selected public-key identity |
| Scripts that confuse failure with “may have executed” | JSON results, exit codes and uncertain outcomes; no automatic write replay after a lost reply |
| Keeping production operations bounded | Environment ceilings, command policies, protected paths, human confirmation and local audit records |

## Get started

### 1. Install the CLI

Linux / macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.ps1 | iex
```

Or download your platform's archive from [Releases](https://github.com/jiamingZhao-zhao/ssh-cli/releases). See [INSTALL.md (中文)](INSTALL.md) for cmd.exe, pinned versions, PATH and checksums.

### 2. Register a host

Replace the documentation address and username below. Host creation prompts for a password:

```sh
ssh-cli group add app-test --env test
ssh-cli host add demo --group app-test --host 192.0.2.10 --user deploy
ssh-cli status -H demo --json
```

For a private key, add `--identity ~/.ssh/id_ed25519`. For an already-loaded local SSH agent, add `--agent`; optionally select one identity with `--agent-key 'SHA256:FULL_FINGERPRINT'` from `ssh-add -l`. A missing selected identity fails authentication rather than trying another key.

### 3. Open the workspace, or stay in your shell

```sh
ssh-cli ui
# Open http://127.0.0.1:7788 in your browser

ssh-cli exec -H demo --json -- df -h
ssh-cli ls -H demo /var/log --json
```

The workspace binds to localhost by default. Files/history occupy about a third of the viewport; resizing them leaves the overview in place. Terminal tabs support scrollback search, match counts and font sizing. Transfers show their current stage and verification status: 100% progress is not proof of a committed remote file.

## Use it with your agent

**Claude Code, Codex, Cursor, GitHub Copilot CLI and OpenCode share the same [SKILL.md](SKILL.md).**

Send the repository link to your agent for the [automatic workflow](SETUP.en.md). You can also run the installer below: it checks the CLI, installs and verifies it if missing, then writes the skill.

<details>
<summary>Manual installation commands</summary>

```sh
git clone https://github.com/jiamingZhao-zhao/ssh-cli.git
cd ssh-cli
```

Linux / macOS, for Claude Code:

```sh
sh scripts/install-skill.sh claude
```

Windows PowerShell:

```powershell
.\scripts\install-skill.ps1 -Agent claude
```

Replace `claude` with `codex`, `cursor`, `copilot` or `opencode` to select the personal installation directory. Identical content is a successful no-op; different content is preserved by default. See the [English skill guide](docs/skills.en.md) for updates, project installations and discovery.

</details>

| Agent | Invocation |
| --- | --- |
| Claude Code | `/ssh-cli Check disk and memory on demo. Read only.` |
| Codex CLI / IDE | `$ssh-cli Check disk and memory on demo. Read only.` |
| Cursor | Type `/` in Agent chat and select `ssh-cli` |
| GitHub Copilot CLI | `/ssh-cli Check disk and memory on demo. Read only.` |
| OpenCode | Ask “Use the ssh-cli skill to check disk and memory on demo, read only.” |

The skill supplies instructions. The agent still needs local command execution and access to the CLI, inventory and credentials in its execution environment. Cloud agents do not inherit SSH keys from your computer. Other Agent Skills hosts can use the same file in their documented discovery directories.

## Commands you can use today

```sh
# Select the host explicitly and inspect it
ssh-cli exec -H demo --timeout 30s --json -- uptime

# Replace paths with your own files and directories
ssh-cli upload -H demo ./artifact.jar /tmp/artifact.jar --json
ssh-cli download -H demo /var/log/app.log ./app.log --json

# Read the host gates, then explain one command
ssh-cli policy show -H demo
ssh-cli policy explain -H demo -- "systemctl restart nginx"

# Inspect recorded operations
ssh-cli audit list --host demo --json

# Check for an update without installing it
ssh-cli update --check
```

Also available: jump hosts, remote-to-remote relay, configuration import/export, batch preflight, explicitly started exec connection reuse and human-only single-command break glass. See the [reference (中文)](docs/usage.md) and [release index](docs/releases/README.md).

## Know the boundaries

- **Policies govern operations through the tool.** Human interactive terminals in standard/admin mode do not check each typed command. Readonly environments refuse unrestricted terminals; file writes still check capabilities and paths.
- **Production is readonly by default.** The built-in `prod` ceiling is readonly. An unattended agent or `--yes` cannot satisfy required human confirmation.
- **A lost reply does not mean nothing happened.** Verify the remote state before retrying an uncertain write, deletion or transfer.
- **Credentials belong in the execution environment.** Passwords use encrypted storage. Host-key checks and policy signatures have distinct roles; neither this skill nor local audit records sandbox a malicious local process.

## Documentation and development

| Topic | Documentation |
| --- | --- |
| Installation, updates and platform archives | [INSTALL.md (中文)](INSTALL.md) |
| Agent setup, invocation and troubleshooting | [English](docs/skills.en.md) / [中文](docs/skills.md) |
| Installation from just a repository link | [English](SETUP.en.md) / [中文](SETUP.md) |
| Configuration, policies, exit codes and detailed usage | [Reference (中文)](docs/usage.md) |
| Iterations | [Release index](docs/releases/README.md), [0.7.28 (中文)](docs/releases/v0.7.28.md) |
| Architecture and roadmap | [PLAN.md (中文)](docs/PLAN.md) |

Building requires Go 1.26+; CI currently uses Go 1.27:

```sh
go build -o ssh-cli ./cmd/ssh-cli
go test ./...
node --test scripts/ui.test.cjs
```

Web assets are embedded, with no frontend build step. Node is only needed for development tests. Local builds report `dev`; release versions are injected from tags.
