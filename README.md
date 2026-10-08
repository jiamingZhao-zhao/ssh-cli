# ssh-cli

零依赖的单文件 SSH 运维 CLI（Go）。远程命令、文件上传下载；凭据加密存储，危险命令拦截，对 agent 友好的输出。

当前包含第 1 次迭代（M0 + M1，以及策略引擎核心）、第 2 次迭代（版本号、`update`、安装脚本），以及强制审计日志和可选的本机 UI。中继、破窗提权、策略 HMAC、GoReleaser 和 SKILL.md 还没做。设计全文见 [docs/PLAN.md](docs/PLAN.md)。安装步骤见 [INSTALL.md](INSTALL.md)。

## 构建

需要 Go 1.22+。六个目标平台都用 `CGO_ENABLED=0`：

```bash
CGO_ENABLED=0 go build -o ssh-cli ./cmd/ssh-cli
```

交叉编译示例：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ssh-cli ./cmd/ssh-cli
```

本地构建的版本号是 `dev`。发布包用 ldflags 写入版本、提交和日期（见 `scripts/package.sh`）：

```bash
CGO_ENABLED=0 go build -ldflags "-X github.com/jiamingZhao-zhao/ssh-cli/internal/version.Version=0.1.0 -X github.com/jiamingZhao-zhao/ssh-cli/internal/version.Commit=abc -X github.com/jiamingZhao-zhao/ssh-cli/internal/version.Date=2026-10-08T00:00:00Z" -o ssh-cli ./cmd/ssh-cli
```

## 安装、版本、更新

```bash
curl -fsSL https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.sh | sh
ssh-cli -h
ssh-cli version
ssh-cli --version
ssh-cli -V
ssh-cli -version
ssh-cli update --check
```

Windows 可以只在 cmd.exe 里安装，不必打开 PowerShell：

```bat
curl.exe -fsSL -o %TEMP%\ssh-cli-install.cmd https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.cmd && %TEMP%\ssh-cli-install.cmd
```

`install.ps1` 仍然可用。两者都默认装到 `%LOCALAPPDATA%\ssh-cli\bin`，目录不在 PATH 里时写入用户 Path。详见 [INSTALL.md](INSTALL.md)。

`version`、`--version`、`-V`、`-version` 打印同一行。`update` 从 GitHub Release 下载当前平台的资产并替换正在运行的二进制，只在执行该命令时发生。没有 `checksums.txt` 时会警告并继续；校验和不匹配则拒绝安装。非交互终端不能确认安装（退出码 253）。仓库和资产名见 [INSTALL.md](INSTALL.md)。

## 配置目录

优先级：`--config` → 环境变量 `SSH_CLI_HOME` → Windows `%APPDATA%\ssh-cli` → macOS/Linux `~/.config/ssh-cli`。

| 文件 | 内容 |
|------|------|
| `hosts.yaml` | 环境标签、分组、主机、命名策略。只有 `passwordRef`，没有明文密码 |
| `secrets.json` | ChaCha20-Poly1305 密文 |
| `known_hosts` | 首次信任（TOFU）的主机密钥 |
| `master.key` | 系统钥匙串不可用时的兜底主密钥（权限 0600，会打印警告） |
| `audit/YYYY-MM-DD.jsonl` | 追加写的审计日志（权限 0600）。不启动 UI 也会写 |

主密钥顺序：系统钥匙串（`zalando/go-keyring`）→ `SSH_CLI_MASTER_KEY`（32 字节的 base64 或 hex）→ `master.key`。

密码只能交互式隐藏输入，或 `--password-stdin`。`--password` 会被拒绝。任何输出都不打印密码。

## 快速开始

示例地址只用文档网段 `192.0.2.0/24`，不要写真实主机。

```bash
ssh-cli env list
ssh-cli group add app-prod --env prod --protected-path /root/app
ssh-cli group add app-test --env test

ssh-cli host add main --group app-prod --host 192.0.2.10 --user viewer --password-stdin --tag app --set-default
ssh-cli host list

ssh-cli exec -H main -- "df -h /"
ssh-cli exec -H main --script ./status.sh
ssh-cli upload -H main ./dist //root/app/dist
ssh-cli download -H main /var/log/app.log ./app.log

ssh-cli policy show -H main
ssh-cli policy explain -H main -- "systemctl restart nginx"
```

`//root/...` 会还原成 `/root/...`，用来避开 Git Bash 对绝对路径的改写。

内置命名策略 `readonly`、`standard`、`admin` 可直接引用，也可以在 `hosts.yaml` 里用同名条目覆盖。自定义 allow/deny 写在这份配置里：可以手改，也可以用本地界面改。命令行还没有 `policy edit`。

## 权限怎么算

一台主机的有效权限是各层允许集合的交集，再减去各层拒绝的并集（含不可关闭的内置硬拒绝）：

- 某一层没写 `allow`，这一层是全集，不把别的层交空。
- 模式 `readonly ⊂ standard ⊂ admin`。环境的 `maxMode` 是天花板，分组写成 `admin` 也不会超过它。
- `confirm` 取并集。确认必须在交互终端里输入主机别名。没有 TTY（包括 agent）直接拒绝，退出码 253。`--yes` 只在有 TTY 时有效。
- 只读 / 标准模式下，解析不了的命令：只读拒绝，标准视为需确认。`curl|bash`、`base64 -d|sh`、`eval`、`source <(...)` 在这两种模式下拒绝。
- 命令用 `mvdan.cc/sh` 解析，`;`、`&&`、管道、`$( )`、`sudo`、`bash -c` 都会检查到。
- 多台主机先整体预检，有一台被拒绝就整批取消；`--skip-denied` 改为跳过被拒绝的主机。
- 一次选择跨了多个环境，必须加 `--allow-cross-env`。选择里包含 `prod` 且多于一台时，整批强制只读。

主机必须属于且只属于一个分组，环境从分组继承，主机上不能写 `env`。`tags` 只用于 `-t` 选择，分组没有 `tags` 字段。

## 环境标签

每次读取配置都会带上四个内置环境。它们的显示名、颜色、`maxMode` 和 `defaultPolicy` 不能改，也不能删除。文件里如果缺了，或者这四项被改过，加载时会改回下表。环境上另外保存的 `breakGlass`、`noDataOutflow` 会留下。

| 名称 | 显示名 | 颜色 | maxMode | 默认策略 |
|------|--------|------|---------|----------|
| `dev` | 开发 | green | admin | standard |
| `test` | 测试 | yellow | standard | standard |
| `preprod` | 预生产 | orange | standard | standard |
| `prod` | 生产 | red | readonly | readonly |

分组可以挂到任何一个环境，包括内置的，例如 `ssh-cli group add hunan-prod --env prod`。

自定义环境可以加、改、删。名字不能是上面四个。还被分组使用的自定义环境不能删。

```bash
ssh-cli env add lab --label 实验 --color green --max-mode admin --default-policy standard
ssh-cli env remove lab
```

`env add prod` 和 `env remove prod` 都会拒绝。

## 审计

每次 `exec`、`upload`、`download` 都会在配置目录追加一条 JSONL，包括策略预检拒绝（内置危险命令、确认类命令、能力开关）、超时、认证失败、连接失败，以及远程非零退出。不记录密码、私钥或明文密钥；命令里的 `password=...` 一类片段会打成 `[redacted]`。

记录字段：`time`（本地时区的 RFC3339）、`op`（`exec` / `upload` / `download` / `policy_check`）、主机别名、分组、环境、命令或 `src`/`dst`、`duration_ms`、`exit_code`、截断到 8KiB 的 `result_summary`、`status`（`ok` / `denied` / `timeout` / `auth` / `connect` / `error`）、`high_risk`、`denied_by_policy`、`reason`、`actor`。`actor` 取环境变量 `SSH_CLI_ACTOR`，否则是 `cli`。

```bash
ssh-cli audit list --host main --since 24h --status denied
ssh-cli audit list --json
ssh-cli audit show <id>
ssh-cli audit tail -n 20
ssh-cli audit tail --follow
```

`--host`、`--group`、`--env`、`--json` 是全局参数。`--since` / `--until` 接受 RFC3339、`YYYY-MM-DD`（直到某天包含那一整天）或 `24h` 这种时长。读取是按天顺序扫描，超出时间窗口的文件会直接跳过。

## 本地界面（可选）

只给人类改同一份 `hosts.yaml`（分组、主机标签、危险命令规则、主机）并查看审计日志。不运行就等于关闭，没有后台进程，也不影响 CLI 和审计。执行命令仍走 `exec` / `upload` / `download`。

```bash
ssh-cli ui
ssh-cli ui --addr 127.0.0.1:7788
```

打开 <http://127.0.0.1:7788> 之后：

- **分组**：新建、修改环境、命名策略、行内 allow/deny/confirm 和受保护路径。有主机的分组不能删，和 `group remove` 一样。
- **标签**：标签只在主机上，给 `ssh-cli -t` 选择用，分组没有 `tags` 字段。可以把一个标签加到该分组下的每台主机，或从全组去掉。
- **危险命令**：内置环境只读；自定义环境可以改 `maxMode` 和 `defaultPolicy`。命名策略的 mode / allow / deny / confirm 可以新建或覆盖。分组和主机的行内规则在对应表单里改。某一层不写 allow 就是全集，写成空列表则会把这一层交空。内置硬拒绝不能关。
- **主机**和**审计**跟以前一样。密码只通过主机表单 POST 进加密存储，不会回显，也不会写入审计。

`relay`、`elevate` 和策略 HMAC 不在这个页面里配置。

默认只监听 `127.0.0.1:7788`。`0.0.0.0` 和其他非回环地址会拒绝，除非显式加上 `--allow-non-loopback`。该参数会打印警告：界面没有认证，不要暴露到网络上。用 Ctrl-C 停止。

## 退出码

远程命令的退出码原样返回。工具自身的错误：

| 码 | 含义 |
|----|------|
| 250 | 参数或配置错误 |
| 251 | 连接失败或超时 |
| 252 | 认证失败 |
| 253 | 策略拒绝，或非 TTY 上的确认被拒绝 |
| 254 | 主机密钥与 `known_hosts` 不一致 |

`--insecure-ignore-host-key` 跳过主机密钥校验，只作为逃生口。

## 测试

```bash
go test ./...
SSH_CLI_INTEGRATION=1 go test ./internal/integration -count=1
```

集成测试在本机用 Docker 启动 `linuxserver/openssh-server`，只连接 `127.0.0.1`。没设置 `SSH_CLI_INTEGRATION=1` 时会跳过。

## 这次没做

`relay`、`status`、`service`、`keys`、`run`、`elevate`、策略 HMAC、命令行 `policy edit`、从 ssh-ops 导入、GoReleaser 发版、SKILL.md。本地界面可以直接改 `hosts.yaml` 里的命名策略和分组 / 主机规则。`config.VerifyPolicy` 仍是留给 HMAC 的空实现。审计日志已经落盘。CI 会把六个平台的压缩包和 `checksums.txt` 作为构建产物上传，但不会自动创建 GitHub Release。
