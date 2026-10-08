# ssh-cli

零依赖的单文件 SSH 运维 CLI（Go）。远程命令、文件上传下载；凭据加密存储，危险命令拦截，对 agent 友好的输出。

当前包含第 1 次迭代（M0 + M1，以及策略引擎核心）和第 2 次迭代（版本号、`update`、安装脚本）。中继、破窗提权、策略 HMAC、GoReleaser 和 SKILL.md 还没做。设计全文见 [docs/PLAN.md](docs/PLAN.md)。安装步骤见 [INSTALL.md](INSTALL.md)。

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

`version`、`--version`、`-V`、`-version` 打印同一行。`update` 从 GitHub Release 下载当前平台的资产并替换正在运行的二进制，只在执行该命令时发生。没有 `checksums.txt` 时会警告并继续；校验和不匹配则拒绝安装。非交互终端不能确认安装（退出码 253）。仓库和资产名见 [INSTALL.md](INSTALL.md)。

## 配置目录

优先级：`--config` → 环境变量 `SSH_CLI_HOME` → Windows `%APPDATA%\ssh-cli` → macOS/Linux `~/.config/ssh-cli`。

| 文件 | 内容 |
|------|------|
| `hosts.yaml` | 环境标签、分组、主机、命名策略。只有 `passwordRef`，没有明文密码 |
| `secrets.json` | ChaCha20-Poly1305 密文 |
| `known_hosts` | 首次信任（TOFU）的主机密钥 |
| `master.key` | 系统钥匙串不可用时的兜底主密钥（权限 0600，会打印警告） |

主密钥顺序：系统钥匙串（`zalando/go-keyring`）→ `SSH_CLI_MASTER_KEY`（32 字节的 base64 或 hex）→ `master.key`。

密码只能交互式隐藏输入，或 `--password-stdin`。`--password` 会被拒绝。任何输出都不打印密码。

## 快速开始

示例地址只用文档网段 `192.0.2.0/24`，不要写真实主机。

```bash
ssh-cli env add prod --label 生产 --color red --max-mode readonly --default-policy readonly
ssh-cli env add test --label 测试 --color yellow --max-mode standard --default-policy standard

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

内置命名策略 `readonly`、`standard`、`admin` 可直接引用，也可以在 `hosts.yaml` 里用同名条目覆盖。自定义 allow/deny 目前写在配置文件里（`policy edit` 属于后续迭代）。

## 权限怎么算

一台主机的有效权限是各层允许集合的交集，再减去各层拒绝的并集（含不可关闭的内置硬拒绝）：

- 某一层没写 `allow`，这一层是全集，不把别的层交空。
- 模式 `readonly ⊂ standard ⊂ admin`。环境的 `maxMode` 是天花板，分组写成 `admin` 也不会超过它。
- `confirm` 取并集。确认必须在交互终端里输入主机别名。没有 TTY（包括 agent）直接拒绝，退出码 253。`--yes` 只在有 TTY 时有效。
- 只读 / 标准模式下，解析不了的命令：只读拒绝，标准视为需确认。`curl|bash`、`base64 -d|sh`、`eval`、`source <(...)` 在这两种模式下拒绝。
- 命令用 `mvdan.cc/sh` 解析，`;`、`&&`、管道、`$( )`、`sudo`、`bash -c` 都会检查到。
- 多台主机先整体预检，有一台被拒绝就整批取消；`--skip-denied` 改为跳过被拒绝的主机。
- 一次选择跨了多个环境，必须加 `--allow-cross-env`。选择里包含 `prod` 且多于一台时，整批强制只读。

主机必须属于且只属于一个分组，环境从分组继承，主机上不能写 `env`。`tags` 只用于 `-t` 选择。

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

`relay`、`status`、`service`、`keys`、`run`、`elevate`、策略 HMAC、`policy edit`、审计日志落盘、从 ssh-ops 导入、GoReleaser 发版、SKILL.md。`internal/audit` 和 `config.VerifyPolicy` 是留给后续接上的空实现。CI 会把六个平台的压缩包和 `checksums.txt` 作为构建产物上传，但不会自动创建 GitHub Release。
