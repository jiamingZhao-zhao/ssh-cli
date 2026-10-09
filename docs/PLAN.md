# ssh-cli 设计提纲（草案 v0.1）

> 目标：用 Go 重写本地 `ssh-ops`（Python + paramiko），产出**零依赖的单文件 CLI**，在没装 Python 的 Windows / macOS / Linux 上拷过去就能用；同时补上凭据加密、危险命令硬拦截、对 agent 友好的输出。
> 状态：M0/M1、策略引擎、安装/`update`、强制审计日志、可选本机 UI，以及 0.3.0 的 `status` / `service` / `keys`、`import ssh-ops`、命名策略编辑已实现。0.3.1 让 `--timeout` 限制 SSH 建连，并为分组增加可选显示名。`relay`、连接复用、`elevate`、策略 HMAC、GoReleaser、SKILL.md 仍未做。下面正文仍是设计草案；用法见 README。版本号仍由发布 tag 经 ldflags 注入，源码里的 `Version` 保持 `dev`。
> 仓库：<https://github.com/jiamingZhao-zhao/ssh-cli>

---

## 1. 目标与非目标

**目标**
- 功能覆盖 ssh-ops 现有 8 个子命令（exec / upload / download / relay / keys / status / service / list-hosts）+ 主机管理。
- 单文件二进制，`CGO_ENABLED=0`，多平台交叉编译。
- 密码不落明文、不进命令行参数、不进 agent 输出。
- 给 agent 用：稳定的退出码、可选 `--json` 输出、UTF-8、脚本可走 stdin。

**非目标（v1 不做）**
- 交互式终端 / 端口转发 / 隧道（需要时直接用系统 `ssh`）。
- 多人共享的凭据服务器、权限体系。
- 守护进程连接复用（放到 P2 评估）。

---

## 2. 功能清单

| # | 功能 | 来源 | 优先级 | 说明 |
|---|------|------|--------|------|
| F1 | `host add/list/remove/edit` | ssh-ops `init_config.py` / `list-hosts` | P0 | 单台增删改，不整文件覆盖；list 掩码显示 |
| F2 | `exec` | ssh-ops | P0 | 远程命令，stdout/stderr 分离，退出码透传，`--timeout` |
| F3 | `exec --script <file>` / stdin | 新增 | P0 | 解决 PowerShell 多层引号问题 |
| F4 | `upload` / `download` | ssh-ops | P0 | SFTP，文件和目录递归，自动 `mkdir -p`，进度可选 |
| F5 | 凭据加密存储 | 新增 | P0 | 见第 4 节 |
| F6 | 密码输入不走 argv | 新增 | P0 | 隐藏输入 / `--password-stdin` |
| F7 | 主机密钥校验（known_hosts，首次信任 TOFU） | 新增 | P0 | ssh-ops 目前不校验 |
| F8 | 环境/分组/主机三层策略 + 危险命令拦截 | 新增（ssh-ops 只是文档约定） | P0 | 见第 5 节 |
| F9 | `relay` 跨机中继 | ssh-ops | P1 | 流式 A→本机→B，三方校验 |
| F10 | `status` | ssh-ops | P1 | 主机/内核/负载/CPU/内存/磁盘/端口/最近登录 |
| F11 | `service` | ssh-ops | P1 | systemctl 封装，服务名白名单正则 |
| F12 | `keys` 公钥审计 | ssh-ops | P1 | 指纹 SHA256 + 注释 + 文件 mtime |
| F13 | `--json` 统一输出 | 新增 | P1 | 方便 agent 解析 |
| F14 | `import ssh-ops` 迁移 | 新增 | P1 | 读旧 `servers.yaml` → 加密入库 → 提示删除明文 |
| F15 | 私钥登录 / ssh-agent | 新增 | P1 | 推荐替代密码 |
| F16 | Git Bash `//` 路径兼容 | ssh-ops | P1 | 自动还原 `//root/...` |
| F17 | 发布流水线 | 新增 | P1 | GitHub Actions + GoReleaser |
| F18 | agent 用 SKILL.md | 新增 | P2 | 替换现有 ssh-ops skill |
| F19 | 连接复用 daemon | 新增 | P2 | 视性能需要再做 |
| F20 | 审计日志（本地记录执行过的命令） | 新增 | 已实现 | JSONL 追加，含策略拒绝；不记录密码。可选 `ssh-cli ui` 只读这份日志 |

---

## 3. 命令设计（草案）

```text
ssh-cli host add <alias> --host 1.2.3.4 [--port 22] --user root [--password-stdin | --identity ~/.ssh/id_ed25519]
ssh-cli host list [--json]
ssh-cli host remove <alias>
ssh-cli host edit <alias> [--host ...] [--port ...] [--user ...] [--password-stdin]

ssh-cli exec   -H main [--timeout 120] [--json] -- "df -h /"
ssh-cli exec   -H main --script ./deploy.sh        # 或: cat deploy.sh | ssh-cli exec -H main --stdin
ssh-cli upload   -H main <local> <remote>
ssh-cli download -H main <remote> <local>
ssh-cli relay  --from a:/etc/x.so --to b:/etc/x.so
ssh-cli status -H main [--json]
ssh-cli service -H main nginx restart
ssh-cli keys   -H main [--path /root/.ssh/authorized_keys] [--json]

ssh-cli import ssh-ops <path/to/servers.yaml>
ssh-cli version
```

- 全局：`-H/--host`（默认取配置里的 `default`）、`-g/--group`、`-t/--tag`、`--env`、`--config`、`--json`、`--yes`（跳过危险确认，仅限人工使用）。
- 退出码：远程命令退出码原样透传；工具自身错误用 `250+`（如 251 连接失败、252 认证失败、253 被拦截），避免和远程码混淆。

---

## 4. 凭据与安全设计

**存储位置**
- Windows：`%APPDATA%\ssh-cli\`；macOS/Linux：`~/.config/ssh-cli/`（可 `--config` / `SSH_CLI_HOME` 覆盖）。
- `hosts.yaml`：只放主机、端口、用户、认证方式、`passwordRef`，**不含任何明文**。
- `secrets.json`：每条 `{nonce, ciphertext}`，算法 ChaCha20-Poly1305（或 AES-256-GCM）。

**主密钥放哪（与 agent-database-cli 的关键区别）**
1. 首选系统钥匙串：Windows 凭据管理器 / macOS Keychain / Linux Secret Service（`zalando/go-keyring`，纯 Go）。
2. 无钥匙串（无桌面的 Linux、CI）：环境变量 `SSH_CLI_MASTER_KEY`。
3. 兜底：本地 key 文件（Unix `0600`，Windows 收紧 ACL 只给当前用户），并打印警告。

**输入与输出**
- 密码只能通过隐藏输入或 `--password-stdin` 传入，拒绝 `--password <明文>`。
- 任何输出、错误信息、日志都不出现密码；`host list` 只显示认证方式。
- SFTP / exec 不把密码拼进远端命令。

**主机密钥**
- 默认 TOFU：首次连接记录指纹到 `known_hosts`，之后指纹变化直接拒绝并提示。
- `--insecure-ignore-host-key` 仅作逃生口。

**边界说明**
- 这套能防“agent 上下文 / 输出 / 仓库里出现明文密码”，**防不住**能以当前用户身份任意执行代码的进程（它也能调钥匙串）。真正收紧靠私钥登录 + 服务器端禁用密码登录。

---

## 5. 安全模型：分组 → 主机，环境作为分组标签 + 策略继承（F8）

### 5.1 层级

```text
分组 (group)   havensphere-prod / havensphere-test / db-prod …   ← 主体，挂策略
 │   env: prod  ← 环境标签：每个分组必填且只能有一个，决定权限天花板
 └─ 主机 (host) main / web-1 …   ← 连接信息 + 可再收紧；env 继承自分组，不能改
标签 (tags)    自由打，仅用于批量选择（-t app），不承载权限
环境定义 (envs) prod / test / dev …   ← 只是标签的定义：label、颜色、maxMode 等
```

- 分组是主体结构；环境不是一层容器，而是挂在分组上的**必填单值标签**。
- 主机必须且只能属于一个分组，环境随分组继承，主机上不能单独改（避免“prod 组里藏一台 dev 主机”绕过上限）。
- 同一业务跨环境 = 建多个分组（`havensphere-prod`、`havensphere-test`），用 tags 做横向选择。
- 环境标签仍然带 `maxMode` 天花板，所以“prod 只读”是标签自带的硬约束，不依赖每个分组自己写对。

### 5.2 模式（mode）

| 模式 | exec | upload / sync | download | relay | service | forward | run 任务 |
|------|------|---------------|----------|-------|---------|---------|----------|
| `readonly` | 只读白名单 | ✗ | ✓（可配） | 只能作源端（可配） | 仅 `status` | ✗（可配） | 仅标记 `allowIn: [prod]` 的任务 + 人工确认 |
| `standard` | 黑名单 + 高危需确认 | ✓ 受保护路径需确认 | ✓ | ✓ | 全部，restart/stop 需确认 | ✓ | ✓ |
| `admin` | 只受内置硬拦截 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### 5.3 权限判定：作用域交集

一台主机执行命令时，它所处的每个作用域（环境标签 → 分组 → 主机）各自给出一个“允许集合”，**最终允许集合 = 各作用域允许集合的交集**，再减去任一作用域的禁止项：

$$
\text{Allowed}(h) = \big(A_{env} \cap A_{group} \cap A_{host}\big) \setminus \big(D_{builtin} \cup D_{env} \cup D_{group} \cup D_{host}\big)
$$

规则细节：

1. **未配置 = 全集**：某层没写 `allow`，该层视为不限制（交集的单位元），否则一层空着就会把所有命令都交没了。
2. **模式也是集合**：`readonly ⊂ standard ⊂ admin`，有效模式 = 各层模式的交集，即最严的那个。env=prod 的 `maxMode: readonly` 会把整组压到只读，下级写 `admin` 无效（加载时告警）。
3. **禁止取并集**：任一层 deny 即禁止；内置硬拦截（`D_builtin`）不可关闭。
4. **需确认取并集**：任一层把某命令标为 confirm，就需要确认。
5. **能力开关、受保护路径**同样按“允许取交集 / 限制取并集”合并。
6. **交集为空要提示**：`ssh-cli policy lint` 在加载时检查某主机有效允许集合是否为空或明显冲突；`policy show -H <host>` 展示最终集合，`policy explain -H <host> -- "<cmd>"` 显示是哪一层把它排除的。
7. **批量执行先整体预检**：`-g` / `-t` 选中多台主机时，先对每台算一遍；只要有一台不允许就整批不执行（可用 `--skip-denied` 改成跳过被拒主机），避免执行到一半。
8. 策略用命名的 `policies` 定义，可挂在环境定义（作为该环境所有分组的默认）、分组、主机上，也可在该处追加 `allow / deny / confirm / protectedPaths`。
9. （可选扩展）主机属于多个分组时，所有分组的集合一起求交集，天然取最严，不会因多归属变宽。v1 默认仍建议一台主机只属于一个分组。

### 5.4 命令检查流程

1. 用 `mvdan.cc/sh` 把命令解析成语法树，展开 `;`、`&&`、`|`、`$( )`、`sudo`、`bash -c` 等，逐条得到真实命令名 + 参数。
2. 解析失败：readonly 直接拒绝；standard 视为高危需确认。
3. 混淆执行（`curl|bash`、`base64 -d|sh`、`eval`、`source <(…)`）在 readonly / standard 一律拒绝。
4. `--script` 脚本逐行同样检查。
5. 命中 confirm：必须在**交互式终端**里输入主机别名确认；非 TTY（agent 调用）直接拒绝，退出码 253。`--yes` 只在 TTY 下有效。

### 5.5 生产环境的“破窗”（break-glass）

现实问题：`main` 就是生产，部署也要在上面重启服务。全只读会导致部署走不通，所以提供两条受控通道：

- **白名单任务**：`run` 任务在配置里显式写 `allowIn: [prod]`（如 `deploy`、`restart-ai`），内容固定、不可带任意参数；执行时人工 TTY 确认。
- **临时提权**：`ssh-cli elevate prod --ttl 15m --reason "…"`，需 TTY 输入环境名确认，到期自动恢复，全程审计。可在配置里整体关闭。

### 5.6 防止策略被篡改

客户端策略如果能被 agent 直接改 YAML 放宽，就等于没有。措施：

- 策略段（envs / groups 的 env 与 policy / policies）用钥匙串里的主密钥做 HMAC 签名；签名不符拒绝加载。
- 修改策略只能走 `ssh-cli policy edit`，需 TTY 确认并展示差异；放宽 prod、或把分组的 `env` 从 prod 改成别的（`group set-env`）都需要额外输入环境名确认。
- `ssh-cli policy show -H <host>` 查看某台主机的有效策略；`ssh-cli policy explain -H <host> -- "<cmd>"` 显示命中哪条规则、来自哪一层。

### 5.7 其他补充

- **按环境分账号**：prod 主机配置低权限账号（如 `viewer`，无 sudo），和客户端策略双保险；需要部署时由白名单任务用单独的 `deploy` 账号（sudoers 只放行指定脚本）。这是真正的硬边界。
- **跨环境批量限制**：一次 `-H` / `-g` / `-t` 选中的主机跨环境时默认拒绝，需 `--allow-cross-env`；包含 prod 的批量操作强制 readonly。
- **数据外流方向**：relay / download 可配置“prod → 非 prod 禁止”。
- **醒目提示**：输出头部带环境标签与颜色（prod 红色），`--json` 带 `env / group / host` 字段。
- **审计日志**：每次执行记录时间、环境、分组、主机、命令、命中规则、退出码、是否提权；不记录密码。
- **边界声明**：客户端检查是减速带，防误操作与 agent 失控；防恶意靠第 5.7 第一条的服务端账号权限。

### 5.8 配置示例

```yaml
version: 1

policies:
  readonly:
    mode: readonly
    allow: [ls, cat, head, tail, grep, less, df, du, free, uptime, ps, ss, netstat,
            "docker ps", "docker logs", "docker stats --no-stream",
            "systemctl status", journalctl, "apps.sh status"]
    capabilities: {upload: false, download: true, relay: source-only, forward: false, service: [status]}
  standard:
    mode: standard
    confirm: ["systemctl restart", "systemctl stop", "docker restart", "docker rm", "apps.sh restart"]
    deny: ["docker system prune -a"]
  admin:
    mode: admin

envs:                       # 环境标签定义
  prod: {label: 生产, color: red,    maxMode: readonly, defaultPolicy: readonly, breakGlass: {enabled: true, maxTtl: 30m}, noDataOutflow: true}
  test: {label: 测试, color: yellow, maxMode: standard, defaultPolicy: standard}
  dev:  {label: 开发, color: green,  maxMode: admin,    defaultPolicy: standard}

groups:
  havensphere-prod:
    env: prod                 # 必填，单值
    protectedPaths: [/root/havensphere-deploy]
    hosts:
      main:
        host: 192.0.2.10      # 示例 IP
        user: viewer
        auth: password
        passwordRef: havensphere-prod.main
        tags: [app, ai]

  havensphere-test:
    env: test
    hosts:
      test-1: {host: 192.0.2.20, user: root, auth: key, identity: ~/.ssh/id_ed25519, tags: [app]}

  sandbox:
    env: dev
    policy: admin             # dev 天花板是 admin，所以生效
    hosts:
      dev-1: {host: 192.0.2.30, user: root, auth: key, identity: ~/.ssh/id_ed25519}

tasks:
  deploy:
    allowIn: [prod, test]
    user: deploy
    script: |
      cd /root/havensphere-deploy && ./scripts/deploy-all.sh && ./apps.sh restart && ./apps.sh status
  restart-ai:
    allowIn: [prod]
    user: deploy
    script: /root/havensphere-deploy/apps.sh restart ai
```

### 5.9 新增命令

```text
ssh-cli group list [--env prod] | add <name> --env prod | remove | set-env <name> <env>
ssh-cli env list | add | remove        # 管理环境标签定义
ssh-cli host add <alias> --group havensphere-prod ...
ssh-cli policy show -H <host> | explain -H <host> -- "<cmd>" | edit
ssh-cli elevate <env> --ttl 15m --reason "..."
ssh-cli run <task> -H <host>
ssh-cli audit [--env prod] [--since 24h]
```

---

## 6. 关键实现

| 模块 | 依赖 | 要点 |
|------|------|------|
| CLI | `spf13/cobra` | 子命令、全局 flag、自动 help/补全 |
| SSH | `golang.org/x/crypto/ssh` | 密码 / 私钥 / keyboard-interactive；`knownhosts` 做 TOFU；连接与命令超时 |
| 文件传输 | `pkg/sftp` | 目录递归、`MkdirAll`、保留权限位、大文件流式 |
| relay | sftp × 2 | 源端流 → `io.TeeReader` 算哈希 → 目标端写；结束后在两端远程 `sha256sum`（兼容 `md5sum`）比对 |
| status | exec 一段固定脚本 | 解析 `uname`、`/proc/loadavg`、`/proc/stat`、`free`、`df`、`ss -lntp`、`last`；兼容缺命令的精简系统 |
| service | exec | 服务名正则 `^[A-Za-z0-9@._-]+$`，动作白名单 |
| keys | `ssh.ParseAuthorizedKey` + `FingerprintSHA256` | 输出类型/指纹/注释/行号 + 文件 mtime |
| 配置 | `gopkg.in/yaml.v3` | 原子写（tmp + rename），单条修改不覆盖他人 |
| 加密 | `x/crypto/chacha20poly1305` + `zalando/go-keyring` | 见第 4 节 |
| 输出 | 自研 `output` 包 | 人读表格 / `--json`；强制 UTF-8，Windows 控制台不再 GBK 崩溃 |
| 路径 | 自研 | 识别 `//root/...` 还原；本地路径用 `filepath`，远端一律 `path`（POSIX） |

---

## 7. 目录结构（规划）

```text
ssh-cli/
├── cmd/ssh-cli/            # main 入口
├── internal/
│   ├── cli/                # cobra 命令定义
│   ├── config/             # hosts.yaml 读写
│   ├── secrets/            # 加密、钥匙串
│   ├── sshclient/          # 连接、认证、known_hosts
│   ├── transfer/           # upload / download / relay
│   ├── guard/              # 危险命令规则
│   ├── remote/             # status / service / keys
│   └── output/             # 表格与 JSON 输出
├── skills/ssh-cli/SKILL.md # 给 agent 的使用说明（P2）
├── docs/PLAN.md            # 本文件
├── .goreleaser.yaml
└── .github/workflows/      # CI + release
```

---

## 8. 构建与发布

- Go 1.22+，`CGO_ENABLED=0`。
- 目标平台：windows/amd64、windows/arm64、darwin/amd64、darwin/arm64、linux/amd64、linux/arm64。
- GitHub Actions：PR 跑 `go vet` + 单测；打 tag 时 GoReleaser 出 Release（zip/tar.gz + checksums）。
- 可选后续：scoop / Homebrew tap / `go install`。

---

## 9. 测试

- 单元测试：config 原子写、加解密往返、guard 规则、路径还原、`authorized_keys` 解析、status 输出解析。
- 集成测试：CI 里起 `linuxserver/openssh-server` 容器，覆盖密码登录、私钥登录、exec 退出码、上传下载目录、relay 校验、TOFU 指纹变化拒绝。
- 不在 CI 里连任何真实服务器。

---

## 10. 里程碑

| 里程碑 | 内容 |
|--------|------|
| M0 | 仓库骨架、cobra、config、secrets（钥匙串 + 兜底）、`host` 子命令 |
| M1 | `exec`（含 `--script`/stdin）、`upload`、`download`、TOFU、UTF-8 输出 |
| M2 | `relay`、`status`、`service`、`keys`、`--json` |
| M3 | guard 危险命令、`import ssh-ops`、私钥 / agent 登录 |
| M4 | GoReleaser + Actions 发布、SKILL.md、替换现有 ssh-ops skill |

---

## 11. 待确认

1. 二进制名用 `ssh-cli` 还是更短的（如 `sshx`）？
2. 配置目录是否接受 `%APPDATA%\ssh-cli` / `~/.config/ssh-cli`？
3. relay 校验默认 sha256（兼容 md5）是否 OK？
4. 危险命令默认“拦截 + `--yes` 放行”，还是默认只警告？
5. 仓库是公开的：确认不放任何真实主机 IP / 账号到示例和测试里。
