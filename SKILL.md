---
name: ssh-cli
description: Use ssh-cli to inspect registered SSH hosts and run authorized commands or file transfers with policy checks, JSON results and local audit records. Use for remote server operations through this tool; not for bypassing its policy or confirmation gates.
---

# SSH CLI

Use the installed `ssh-cli` and the user's existing inventory. Check `ssh-cli version`, `ssh-cli host list --json` and the relevant subcommand's `--help` before an unfamiliar operation. Use `-H <alias>` explicitly so the configured default cannot silently select another host.

- Read state first (`status`, `ls`, `history` or an allowed `exec`), then perform only the remote changes the user requested.
- Prefer `--json` for structured results. Tool errors use 250 (usage), 251 (connection), 252 (authentication), 253 (policy/confirmation) and 254 (host key). Remote exit codes pass through and can overlap; inspect `results[].status`, `outcome`, `error` and output as well as the process status.
- `outcome: unknown`, a transport failure or a lost response means the command may have run. Inspect remote state and existing audit records before considering another attempt. A nonzero remote exit can also leave side effects. Never automatically replay a write, transfer or delete.
- Respect `readonly`, protected paths, `noDataOutflow`, cross-environment restrictions and denied commands. Do not edit policies, move a host to another environment, clear host-key trust, use `--insecure-ignore-host-key`, forge browser confirmation requests or change command syntax to evade a denial.
- Confirmation requires the user's interactive TTY. `--yes` does not authorize a noninteractive agent. Stop that operation and explain the exact requested human action; independent authorized reads may continue.
- `elevate` is a human-only, single-host, single-command break-glass path, disabled by default. Do not invoke it or configure break glass on behalf of an unattended agent. Its TTL closes the SSH operation; it cannot roll back changes or stop detached remote processes.
- Credentials belong in configured secret storage, a private key reference or the local SSH agent. Never put passwords/tokens into command arguments, audit annotations, generated documentation or chat output. History/audit redaction is heuristic; avoid retrieving secret-bearing files or commands unnecessarily.
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

See [README.md](README.md) for setup and [docs/releases/v0.7.26.md](docs/releases/v0.7.26.md) for integrity, break-glass and reuse boundaries.
