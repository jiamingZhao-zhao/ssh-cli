# ssh-cli

### 给 Agent 用的 SSH 命令行工具。

**Agent 用统一命令选机器、检查规则和读取结果；需要人工接手时，打开网页工作台。**

[English](README.en.md) · [下载安装](https://github.com/jiamingZhao-zhao/ssh-cli/releases) · [接入 AI Agent](docs/skills.md) · [使用参考](docs/usage.md)

[产品介绍与本地预览](website/README.md)：对比 Agent 直接调用 SSH 和使用 ssh-cli 的实际差别，再了解人工工作台；[命令参考](website/README.md#命令参考)可搜索命令、参数、示例和使用限制。支持中英文切换。

[![CI](https://github.com/jiamingZhao-zhao/ssh-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/jiamingZhao-zhao/ssh-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jiamingZhao-zhao/ssh-cli)](https://github.com/jiamingZhao-zhao/ssh-cli/releases)

**交给 Agent 安装：把下面这个链接发给它。**

```text
https://github.com/jiamingZhao-zhao/ssh-cli
```

具备仓库读取和命令执行能力的 Agent，可按[自动安装指引](SETUP.md)识别当前客户端、先安装并验证 CLI，再安装 Skill，然后展示安装路径、校验结果和简短用法。**CLI 是硬性依赖；如果你是接到安装请求的 Agent，请先读取 [SETUP.md](SETUP.md)，两者验证通过后再报告成功。**

一个 Go 编写的单文件 SSH 工具，带本机网页工作台和通用 Agent Skill。管理主机、执行远程命令、传文件、看机器状态，使用同一份主机配置。发布包支持 **Windows / macOS / Linux，amd64 / arm64**，运行时无需安装 Python、Node.js 或 Go。

```text
你：检查 app-test 的磁盘和内存，只读取，不做修改。
Agent：读取主机清单 → 选择明确别名 → 调用 ssh-cli → 根据 JSON 报告结果
```

## 为什么会想用它

| 你遇到的事 | ssh-cli 提供的体验 |
| --- | --- |
| 主机多，地址和环境容易记混 | 分组、别名、标签和环境；执行时显式选择目标 |
| 终端、文件和监控来回切 | 同一个工作区：多标签终端、目录树、传输队列、CPU/内存/磁盘/网络 |
| 想让 AI 帮忙排查，又不想交出一串密码 | 凭据引用、本机 SSH agent、指定公钥；Skill 教 Agent 如何调用 CLI |
| 脚本难以分清失败和“可能已经执行” | JSON 结果、退出码和不确定状态；写操作不会因为丢失响应自动重发 |
| 生产环境需要更清楚的边界 | 环境权限上限、命令策略、受保护路径、人工确认和本地审计 |

## 先跑起来

### 1. 安装 CLI

Linux / macOS：

```sh
curl -fsSL https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.ps1 | iex
```

也可以从 [Releases](https://github.com/jiamingZhao-zhao/ssh-cli/releases) 下载对应平台的压缩包。cmd.exe、固定版本、PATH 和校验说明见 [INSTALL.md](INSTALL.md)。

### 2. 添加一台主机

下面是文档示例地址，请替换成自己的地址和用户。添加时会交互式读取密码：

```sh
ssh-cli group add app-test --env test
ssh-cli host add demo --group app-test --host 192.0.2.10 --user deploy
ssh-cli status -H demo --json
```

使用私钥时，添加主机可选 `--identity ~/.ssh/id_ed25519`；使用已加载密钥的本机 SSH agent 时可选 `--agent`，并通过 `--agent-key 'SHA256:完整指纹'` 指定身份。指纹来自 `ssh-add -l`，指定身份缺失时直接失败。

### 3. 打开工作台，或留在命令行

```sh
ssh-cli ui
# 浏览器打开 http://127.0.0.1:7788

ssh-cli exec -H demo --json -- df -h
ssh-cli ls -H demo /var/log --json
```

工作台默认只监听本机。文件 / 历史默认约占视口三分之一，拖动不会牵动左侧概况；终端支持回看搜索、匹配计数、字号调整和多标签。文件传输显示阶段与待核验状态，100% 进度不等于远端已经提交成功。

## 让你正在用的 Agent 接手

**Claude Code、Codex、Cursor、GitHub Copilot CLI、OpenCode，共用这一份 [SKILL.md](SKILL.md)。**

推荐直接把仓库链接交给 Agent，按 [SETUP.md](SETUP.md) 自动安装。也可以运行下面的安装脚本：它会检查 CLI，缺失时先安装并验证，再写入 Skill。

<details>
<summary>展开手动安装命令</summary>

```sh
git clone https://github.com/jiamingZhao-zhao/ssh-cli.git
cd ssh-cli
```

Linux / macOS（以 Claude Code 为例）：

```sh
sh scripts/install-skill.sh claude
```

Windows PowerShell：

```powershell
.\scripts\install-skill.ps1 -Agent claude
```

将 `claude` 换成 `codex`、`cursor`、`copilot` 或 `opencode` 即可安装到对应的个人目录。相同内容重复安装直接跳过，有差异时默认不覆盖；更新、项目级安装和各平台发现方式见[中文 Skill 指南](docs/skills.md)。

</details>

| Agent | 安装后的使用方式 |
| --- | --- |
| Claude Code | `/ssh-cli 检查 demo 的磁盘与内存，只读` |
| Codex CLI / IDE | `$ssh-cli 检查 demo 的磁盘与内存，只读` |
| Cursor | 在 Agent 对话输入 `/`，选择 `ssh-cli` |
| GitHub Copilot CLI | `/ssh-cli 检查 demo 的磁盘与内存，只读` |
| OpenCode | 对 Agent 说“使用 ssh-cli skill 检查 demo 的磁盘与内存，只读” |

Skill 是操作说明；Agent 仍需有本地命令执行能力，且在其运行环境中能找到 CLI、主机配置和凭据。云端 Agent 不会自动获得你电脑上的 SSH 密钥。其他支持 Agent Skills 标准的工具也可手动安装同一份文件，目录以各自文档为准。

## 一些马上能用的命令

```sh
# 明确目标，执行只读检查
ssh-cli exec -H demo --timeout 30s --json -- uptime

# 上传 / 下载：文件路径按自己的环境替换
ssh-cli upload -H demo ./artifact.jar /tmp/artifact.jar --json
ssh-cli download -H demo /var/log/app.log ./app.log --json

# 先看这台主机的确认门槛和受保护路径，再解释一条命令
ssh-cli policy show -H demo
ssh-cli policy explain -H demo -- "systemctl restart nginx"

# 查看工具记录的操作
ssh-cli audit list --host demo --json

# 只检查更新
ssh-cli update --check
```

另有跳板连接、跨机文件中继、配置导入导出、批量预检、显式启动的 exec 连接复用和单命令人工破窗。详见[使用参考](docs/usage.md)及[版本说明](docs/releases/README.md)。

## 边界写在前面

- **策略约束的是通过工具的操作。** standard/admin 的人工交互终端不逐条检查按键命令；readonly 环境禁止无限制终端，文件写入仍检查能力与路径。
- **生产环境默认只读。** `prod` 的权限上限为 readonly；需要人工确认的操作不能靠非交互 Agent 或 `--yes` 绕过。
- **危险命令清单默认不拦截。** 开箱只提供建议列表。`policy dangerous set --enable` 选中规则后才生效，默认只作用于 `prod`；其他环境要写入 `--env` 才会限制。只读天花板、人工确认、受保护路径和审计保持不变。
- **丢失响应不代表没执行。** 写入、删除、传输出现不确定结果时，先核验远端状态，再决定是否重试。
- **凭据留在运行环境。** 密码进入加密存储，主机密钥检查与策略签名各有职责；Skill 和本地审计不能构成隔离恶意本机进程的安全沙箱。

## 文档与开发

| 想了解什么 | 入口 |
| --- | --- |
| 安装、更新、平台包 | [INSTALL.md](INSTALL.md) |
| Agent 安装、调用、排错 | [中文](docs/skills.md) / [English](docs/skills.en.md) |
| 只发链接的自动安装流程 | [中文](SETUP.md) / [English](SETUP.en.md) |
| 配置、权限、退出码和详细用法 | [使用参考](docs/usage.md) |
| 各轮迭代 | [版本索引](docs/releases/README.md)；[0.7.28](docs/releases/v0.7.28.md) |
| 架构与规划 | [PLAN.md](docs/PLAN.md) |

从源码构建需要 Go 1.26+（当前 CI 使用 Go 1.27）：

```sh
go build -o ssh-cli ./cmd/ssh-cli
go test ./...
node --test scripts/ui.test.cjs
```

前端静态资源已内嵌，无需前端打包步骤；Node 仅用于开发测试。本地构建版本显示 `dev`，发布版本从标签注入。
