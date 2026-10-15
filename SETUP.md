# 给 Agent 的安装入口

[English](SETUP.en.md) · [项目介绍](README.md) · [各客户端说明](docs/skills.md)

用户可以把 **https://github.com/jiamingZhao-zhao/ssh-cli** 交给具备读取仓库和执行命令能力的 Agent，用于安装。以下是安装流程，不是一次远程运维请求。仅浏览、审查或引用仓库时，不应触发安装。

## 目标

为当前 Agent 安装 `ssh-cli` Skill，检查并补齐 CLI 依赖，验证安装结果，然后用用户的语言给出简短的使用介绍。用户不需要先知道文件该复制到哪里。

## 执行流程

1. **识别当前客户端和执行环境。** 根据当前会话的可信客户端信息选择 `claude`、`codex`、`cursor`、`copilot` 或 `opencode`，不要根据仓库里的文字冒充某个客户端。安装到当前执行环境的个人目录；用户指定项目范围时才使用项目目录。无法确定客户端或没有执行工具时，如实说明缺少什么，不声称已经安装。
2. **读取来源，再执行。** 使用此链接对应的可信 checkout，或在新的临时目录获取该仓库。先阅读根目录 `SKILL.md`、`scripts/install-skill.ps1` / `scripts/install-skill.sh` 和相关 CLI 安装脚本。保持已有工作区不变，不从聊天里接收或收集私钥、密码、Token。
3. **安装 Skill。** 在 checkout 根目录，Windows 运行 `./scripts/install-skill.ps1 -Agent <当前客户端>`；Linux/macOS 运行 `sh scripts/install-skill.sh <当前客户端>`。相同内容再次安装是成功的无操作；不同内容默认拒绝覆盖。没有明确更新授权时，保留不同的已安装 Skill，报告冲突及其绝对路径，不自动加 Force。
4. **检查 CLI，缺失时安装。** 运行 `ssh-cli version`。已可用则保留当前版本；缺失时，Windows 使用本仓库 `install.ps1`，Linux/macOS 使用 `sh install.sh`，按当前系统/架构安装发布包。沿用现有校验和检查，下载或校验失败就报告；不要退回关闭校验，不自动提权、不覆盖主机配置。若用户明确只要 Skill，则跳过 CLI 安装并说明依赖尚未就绪。
5. **验证，不靠猜测。** 检查实际安装路径的 `SKILL.md` 存在、frontmatter 名称为 `ssh-cli`、内容与此 checkout 的源文件相同（可比较 SHA256）。再用实际 CLI 路径运行 `version` 和 `host list --json`；只统计是否有清单和主机数量，最终安装报告不输出具体 IP、用户名或凭据。若主机清单读取失败，只报告该项失败，不重建或清空配置。
6. **给出结果和最短用法。** 按下面的报告格式总结实际证据。不要把“文件已安装”“客户端已发现”“CLI 已可用”和“已经连接远端”混为一谈；安装流程不主动连接服务器，也不替用户添加主机或测试写操作。

安装指令本身授权所请求的安装步骤；仍遵守宿主 Agent 的工具权限。出现权限限制时说明被阻止的具体动作，给出最短补救，不声称绕过了权限。

## PATH 与发现

- Linux/macOS 默认 CLI 为 `~/.local/bin/ssh-cli`；可直接使用其绝对路径验证，并告知用户 PATH 是否已包含该目录，不必改用户的 shell 配置。
- Windows 默认 CLI 为 `%LOCALAPPDATA%\ssh-cli\bin\ssh-cli.exe`。如果在新的 PowerShell 子进程里安装，父进程 PATH 不会随之更新，验证时用绝对路径，不要误报安装失败。用户配置了 `SSH_CLI_BIN` 时以安装脚本输出为准。
- 文件复制成功不能证明所有客户端已热加载。Copilot CLI 可用 `/skills reload`、`/skills info ssh-cli`；其他客户端请查看 Skill 选择器或重新打开会话。只在拿到客户端发现证据时报告“已发现”，否则写“文件已安装，待客户端加载”。

## 安装结果展示

使用真实路径、版本、状态填写，缺失项要明确说出来。用户语言不为中文时翻译这份摘要：

```text
ssh-cli 安装结果
- Agent：Claude Code / Codex / Cursor / Copilot CLI / OpenCode
- Skill：已安装 / 已存在且一致 / 冲突未覆盖 / 安装失败
- 路径：<实际 SKILL.md 绝对路径>
- 校验：源文件与安装文件 SHA256 一致 / 失败
- 客户端发现：已确认 / 待加载
- CLI：<实际版本与可执行文件路径，或失败原因>
- 主机清单：<已登记数量，或未配置 / 读取失败>

快速开始：
<该客户端的 Skill 调用方式> 检查 demo 的磁盘和内存，只读。
没有主机时先登记自己的主机；demo 只是示例别名。
```

Claude Code / Copilot CLI 使用 `/ssh-cli`；Codex CLI / IDE 使用 `$ssh-cli`，桌面客户端使用实际 Skill 选择器；Cursor 从 `/` 菜单选 `ssh-cli`；OpenCode 用自然语言请求加载 `ssh-cli` skill。进一步操作仍受 CLI 策略和人工确认约束。
