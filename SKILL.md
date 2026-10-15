---
name: ssh-cli
description: Use ssh-cli for SSH server health checks, remote commands, logs, service operations and file transfers using the user's registered hosts. Use when asked to inspect or operate remote Linux servers through ssh-cli, including Chinese SSH 运维 requests. Respect policy and confirmation gates; do not use for unrelated local development.
---

# SSH CLI

Use this instruction-only Agent Skill with any host that supports standard `SKILL.md` files and local command execution. It needs no provider API, MCP server or provider-specific tools. Do not assume that installing the skill installs the CLI, grants shell access or makes local credentials available in a cloud sandbox.

Use the installed `ssh-cli` and the user's existing inventory. Check `ssh-cli version`, `ssh-cli host list --json` and the relevant subcommand's `--help` before an unfamiliar operation. If the executable or inventory is unavailable, report the missing prerequisite; do not invent a host or fall back to another SSH tool. Use `-H <alias>` explicitly so the configured default cannot silently select another host.

- Read state first (`status`, `ls`, `history` or an allowed `exec`), then perform only the remote changes the user requested.
- Prefer `--json` for structured results. Tool errors use 250 (usage), 251 (connection), 252 (authentication), 253 (policy/confirmation) and 254 (host key). Remote exit codes pass through and can overlap; inspect `results[].status`, `outcome`, `error` and output as well as the process status.
- `outcome: unknown`, a transport failure or a lost response means the command may have run. Inspect remote state and existing audit records before considering another attempt. A nonzero remote exit can also leave side effects. Never automatically replay a write, transfer or delete.
- Respect `readonly`, protected paths, `noDataOutflow`, cross-environment restrictions and denied commands. Do not edit policies, move a host to another environment, clear host-key trust, use `--insecure-ignore-host-key`, forge browser confirmation requests or change command syntax to evade a denial.
- Confirmation requires the user's interactive TTY. `--yes` does not authorize a noninteractive agent. Stop that operation and explain the exact requested human action; independent authorized reads may continue.
- `elevate` is a human-only, single-host, single-command break-glass path, disabled by default. Do not invoke it or configure break glass on behalf of an unattended agent. Its TTL closes the SSH operation; it cannot roll back changes or stop detached remote processes.
- Credentials belong in configured secret storage, a private key reference or the local SSH agent. Never put passwords/tokens into command arguments, audit annotations, generated documentation or chat output. History/audit redaction is heuristic; avoid retrieving secret-bearing files or commands unnecessarily.
- With agent authentication, honor the saved `agentKey` SHA256 fingerprint. If that identity is absent, report the authentication failure; do not clear the selector, switch identities or change authentication to get around it. `host edit --agent-key` changes configuration, not a per-command credential override; perform it only when the user requested that change.
- Upload and relay stage a temporary remote file before commit; download stages locally. Directory transfers commit files separately and are not transactions. A canceled/lost reply can still occur after a final rename, so verify the destination.
- `audit protect` establishes the current logs as an integrity baseline; `audit verify --json` checks it. Local HMAC cannot defeat a process that can read the signing key or roll back logs and their checkpoint together. Keep a checkpoint in an independently trusted store when required. Never re-sign altered records to conceal a verification failure.
- For repeated literal `exec` commands, an already-running `ssh-cli daemon serve` supports `exec --daemon -H <alias> --json -- <command>`. It does not start itself, accept confirmation-required commands, execute stdin scripts, reuse file transfers or retry on failure. Default CLI calls remain direct. `session run` remains an alternative for several commands in one invocation.

Examples (adapt aliases and paths to the inventory):

```text
ssh-cli status -H app --json
ssh-cli exec -H app --json -- df -h
ssh-cli ls -H app /var/log --json
ssh-cli audit list --host app --json
ssh-cli upload -H app ./artifact.jar /tmp/artifact.jar --json
```

When reporting a result, identify the host, the requested action, the observed outcome and any uncertainty. Distinguish "denied", "failed" and "unknown"; do not describe an attempted operation as completed without a final result.

For installation and provider-specific discovery, see the [Chinese guide](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/docs/skills.md) or [English guide](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/docs/skills.en.md). Use the installed command's help as the authority for flags supported by that version. The [0.7.26 boundaries](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/docs/releases/v0.7.26.md) and [0.7.27 agent identity behavior](https://github.com/jiamingZhao-zhao/ssh-cli/blob/main/docs/releases/v0.7.27.md) provide additional context when needed.
