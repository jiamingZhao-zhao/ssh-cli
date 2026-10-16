---
name: ssh-cli
description: Use ssh-cli for SSH server health checks, remote commands, logs, service operations and file transfers using the user's registered hosts. Use when asked to inspect or operate remote Linux servers through ssh-cli, including Chinese SSH 运维 requests. Respect policy and confirmation gates; do not use for unrelated local development.
---

# SSH CLI

Use this Agent Skill with any host that supports standard `SKILL.md` files and local command execution. It needs no provider API, MCP server or provider-specific tools. A working `ssh-cli` is a mandatory installation prerequisite; copying this file alone is not completed setup. Installation does not grant shell access or make local credentials available in a cloud sandbox.

## Required CLI setup

Before reporting installation success or using the skill, verify `ssh-cli version` in the agent's execution environment. Check PATH and `SSH_CLI_BIN` (an installation directory), or the default `~/.local/bin/ssh-cli` / `%LOCALAPPDATA%\ssh-cli\bin\ssh-cli.exe`; use an absolute path when PATH has not refreshed. Reuse a working version. If a found executable fails, report the failure rather than replacing it automatically.

If the CLI is missing, an installation request includes this dependency. Obtain a trusted checkout of https://github.com/jiamingZhao-zhao/ssh-cli in a fresh temporary directory, read its installer, then run `install.ps1` on Windows or `sh install.sh` on Linux/macOS. Require release checksum verification, including unsetting any inherited `SSH_CLI_ALLOW_MISSING_CHECKSUM=1` for that invocation. Do not elevate privileges, disable verification or overwrite host configuration. If execution permissions, download, checksum or version verification fails, stop setup and report it as incomplete. A request to omit CLI installation cannot produce a completed installation of this skill; explain the mandatory dependency instead of claiming success. For full client setup use [SETUP.md](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/SETUP.md) or [SETUP.en.md](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/SETUP.en.md).

Verify the actual executable's `version`, report its path and version, then read `host list --json` without connecting to servers. An empty inventory does not prevent installation; report that hosts still need configuring. A failed inventory read is a separate configuration issue, not permission to clear or recreate it. Resume the user's authorized operation only when its target is available. Do not invent a host or fall back to another SSH tool.

## Remote operations

Use the installed `ssh-cli` and the user's existing inventory. Check the relevant subcommand's `--help` before an unfamiliar operation. Use `-H <alias>` explicitly so the configured default cannot silently select another host.

- Read state first (`status`, `ls`, `history` or an allowed `exec`), then perform only the remote changes the user requested.
- Before a change, run `ssh-cli policy show -H <alias> --json`. It is read-only and does not connect. Use `confirm`, `protectedPaths`, `equivalence` and `envRules` (`maxMode`, `defaultPolicy`, `noDataOutflow`, `breakGlass`) instead of discovering a gate by exiting 253. `policy explain -H <alias> -- <command>` checks one command the same way `exec` will see it.
- Prefer `--json` for structured results. Tool errors use 250 (usage), 251 (connection), 252 (authentication), 253 (policy/confirmation) and 254 (host key). Remote exit codes pass through and can overlap; inspect `results[].status`, `outcome`, `error` and output as well as the process status.
- `outcome: unknown`, a transport failure or a lost response means the command may have run. Inspect remote state and existing audit records before considering another attempt. A nonzero remote exit can also leave side effects. Never automatically replay a write, transfer or delete.
- Respect `readonly`, protected paths, `noDataOutflow`, cross-environment restrictions and denied commands. Do not edit policies, move a host to another environment, clear host-key trust, use `--insecure-ignore-host-key`, forge browser confirmation requests or change command syntax to evade a denial. `docker restart` / `systemctl restart` / `apps.sh restart` also gate `stop` and `start` (and `docker kill`). `docker stop` also gates `restart` and `kill`, not `start` alone. `docker container <verb>` is the same verb. Running `./script.sh`, `/path/script.sh`, `sh script.sh` or `source script.sh` is an uninspected script and needs confirmation; pasting the script text is checked command by command, which is not a way around a gated command inside it.
- Pass remote argv as separate arguments so quotes survive. `ssh-cli exec -H app -- curl -d '{"k":"v"}' http://127.0.0.1/api` and `ssh-cli exec -H app -- sh -c 'mkdir -p /a /b'` keep those arguments intact. One argument is still a remote shell script (`exec -H app -- "df -h / | head"`). Do not pre-join words in a way that drops quotes, and do not wrap a command only to dodge a gate.
- On Git Bash, an absolute Unix path such as `/etc/nginx` may arrive rewritten as `D:/soft/git/Git/etc/nginx`. ssh-cli warns and does not rewrite it. Pass `//etc/nginx`, or set `MSYS_NO_PATHCONV=1` for that command. The `//` form is restored to `/etc/nginx`.
- `upload --json` reports `bytes`, `durationMs` and `sha256` (regular-file contents in plan order). `--backup` copies an existing file to `<path>.ssh-cli.bak` before replacement. `--confirm-overwrite` asks for the host alias and exits 253 without a TTY. The default is still a silent replace.
- `exec --forward-stdin` copies local stdin to one remote command (`crontab -`). It is not combined with `--script`, `--stdin`, `--daemon`, or more than one host.
- Confirmation requires the user's interactive TTY. `--yes` does not authorize a noninteractive agent. Stop that operation and explain the exact requested human action; independent authorized reads may continue.
- `elevate` is a human-only, single-host, single-command break-glass path, disabled by default. Do not invoke it or configure break glass on behalf of an unattended agent. Its TTL closes the SSH operation; it cannot roll back changes or stop detached remote processes.
- Credentials belong in configured secret storage, a private key reference or the local SSH agent. Never put passwords/tokens into command arguments, audit annotations, generated documentation or chat output. History/audit redaction is heuristic; avoid retrieving secret-bearing files or commands unnecessarily.
- With agent authentication, honor the saved `agentKey` SHA256 fingerprint. If that identity is absent, report the authentication failure; do not clear the selector, switch identities or change authentication to get around it. `host edit --agent-key` changes configuration, not a per-command credential override; perform it only when the user requested that change.
- Upload and relay stage a temporary remote file before commit; download stages locally. Directory transfers commit files separately and are not transactions. A canceled/lost reply can still occur after a final rename, so verify the destination.
- `audit protect` establishes the current logs as an integrity baseline; `audit verify --json` checks it. Local HMAC cannot defeat a process that can read the signing key or roll back logs and their checkpoint together. Keep a checkpoint in an independently trusted store when required. Never re-sign altered records to conceal a verification failure.
- Consecutive `exec` calls do not reuse a connection unless you already started `ssh-cli daemon serve` and pass `exec --daemon`. The daemon is not auto-started, does not accept confirmation-required commands, does not run `--stdin` / `--script` / `--forward-stdin`, does not cover file transfer, and does not retry. Default calls stay direct. `session run` is the in-process alternative for several commands in one invocation. Automatic reuse across ordinary CLI calls is not implemented.

Examples (adapt aliases and paths to the inventory):

```text
ssh-cli status -H app --json
ssh-cli policy show -H app --json
ssh-cli exec -H app --json -- df -h
ssh-cli exec -H app --json -- curl -d '{"k":"v"}' http://127.0.0.1/api
ssh-cli ls -H app /var/log --json
ssh-cli audit list --host app --json
ssh-cli upload -H app ./artifact.jar /tmp/artifact.jar --json
```

When reporting a result, identify the host, the requested action, the observed outcome and any uncertainty. Distinguish "denied", "failed" and "unknown"; do not describe an attempted operation as completed without a final result.

For installation and provider-specific discovery, see the [Chinese guide](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/docs/skills.md) or [English guide](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/docs/skills.en.md). Use the installed command's help as the authority for flags supported by that version. The [0.7.26 boundaries](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/docs/releases/v0.7.26.md) and [0.7.27 agent identity behavior](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/docs/releases/v0.7.27.md) provide additional context when needed.
