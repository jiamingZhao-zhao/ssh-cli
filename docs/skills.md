# 把 ssh-cli 接入你的 AI Agent

[English](skills.en.md) · [返回首页](../README.md) · [Skill 源文件](../SKILL.md)

**推荐方式：把 https://github.com/jiamingZhao-zhao/ssh-cli 发给你的 Agent。** 首页会把安装请求引导到 [SETUP.md](../SETUP.md)：识别客户端、安装与校验 Skill、检查 CLI，最后展示路径、版本、清单状态和一句可直接使用的提示词。下面是手动步骤和各平台位置。

## 先分清两件事

**CLI 负责连服务器，Skill 教 Agent 怎样调用 CLI。** 本仓库提供标准 `SKILL.md`，安装时只有目录因客户端而异；不依赖某一家模型的 API、MCP 服务或专用工具名称。

需要在 **Agent 实际执行命令的环境** 中安装 `ssh-cli`。安装脚本会补齐这个依赖；主机可在安装完成后登记。使用远程操作前检查：

```sh
ssh-cli version
ssh-cli host list --json
```

如果 Agent 跑在远端容器、WSL 或云端，这两条命令也要在那里能运行。安装 Skill 不会把本机凭据上传过去，也不会给 Agent 额外权限。只有普通聊天、没有命令执行能力的客户端，不能仅靠这份 Skill 连接你的 SSH 主机。

## 安装：选一个你正在使用的 Agent

先获取仓库，在其根目录执行安装脚本：

```sh
git clone https://github.com/jiamingZhao-zhao/ssh-cli.git
cd ssh-cli
```

Linux / macOS：

```sh
sh scripts/install-skill.sh claude
```

Windows PowerShell：

```powershell
.\scripts\install-skill.ps1 -Agent claude
```

可选名称：`claude`、`codex`、`cursor`、`copilot`、`opencode`。**CLI 是安装 Skill 的硬性依赖。** 脚本复用已可用的 CLI，缺失时自动调用仓库的 CLI 安装脚本并强制校验发布包，只有 `version` 验证通过才写入 `SKILL.md`。失败时保留原 Skill 或不创建新文件；不修改 Agent 设置、放宽执行权限或复制 SSH 配置。已有文件一致时也会检查 CLI，有差异默认拒绝覆盖；先检查旧内容，确认需要更新时再加 `--force` / `-Force`。

| Agent | 个人安装目录 | 项目安装目录 | 如何使用 / 官方说明 |
| --- | --- | --- | --- |
| Claude Code | `~/.claude/skills/ssh-cli/` | `.claude/skills/ssh-cli/` | `/ssh-cli`；[Claude 文档](https://code.claude.com/docs/en/skills) |
| Codex | `~/.agents/skills/ssh-cli/` | `.agents/skills/ssh-cli/` | CLI / IDE 使用 `$ssh-cli` 或 `/skills`；[OpenAI 文档](https://learn.chatgpt.com/docs/build-skills) |
| Cursor | `~/.cursor/skills/ssh-cli/` | `.cursor/skills/ssh-cli/` | 在 Agent 对话中输入 `/` 选择；[Cursor 文档](https://cursor.com/docs/skills) |
| GitHub Copilot CLI | `~/.copilot/skills/ssh-cli/` | `.github/skills/ssh-cli/` | `/ssh-cli`；[Copilot CLI 文档](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills) |
| OpenCode | `~/.config/opencode/skills/ssh-cli/` | `.opencode/skills/ssh-cli/` | 请 Agent 加载 `ssh-cli` skill；[OpenCode 文档](https://opencode.ai/docs/skills) |

`~` 表示用户主目录，Windows 通常为 `C:\Users\你的用户名`。表格针对各客户端支持的本地 Skill 机制；不同版本、组织策略和云端环境可能影响发现与执行能力，不能等同于全部客户端都已做过真实 SSH 联调。

### 只在一个项目里启用

传入已有项目目录；不要把项目目录误写成 Skill 目录：

```sh
sh scripts/install-skill.sh claude --project /path/to/your-project
```

```powershell
.\scripts\install-skill.ps1 -Agent claude -Project 'D:\code\your-project'
```

手动复制或使用客户端自己的安装器时，同样必须先准备 CLI 并通过 `ssh-cli version` 验证；只复制 `SKILL.md` 不算安装完成。主机登记是后续使用步骤，不是安装成功的前提。避免在同一客户端的多个可发现目录里重复安装同名 Skill。

## 装好后，直接这样说

Claude Code / Copilot CLI：

```text
/ssh-cli 检查 demo 的磁盘和内存，只读，不修改任何文件。
```

Codex CLI / IDE：

```text
$ssh-cli 检查 demo 的磁盘和内存，只读，不修改任何文件。
```

Codex 桌面客户端可从 Skill 选择器选择；具体提及符号以当前客户端为准。Cursor 在 `/` 菜单中选择 `ssh-cli` 后写同样的需求；OpenCode 或其他支持 Skill 的 Agent 可以直接说：

```text
使用 ssh-cli skill，先列出已登记主机，再检查 demo 的磁盘和内存，只读。
```

调用时先跑 `ssh-cli policy show -H <别名> --json`（只读，不连接），用 `confirm`、`protectedPaths`、`equivalence`、`envRules` 和 `dangerousCommands` 看确认门槛。`dangerousCommands.catalog` 只是建议列表，`enforcedHere` 为 false 时不要把它当成已经生效的拒绝。不要靠退出码 253 试探。多参数 `exec` 会保留引号，例如 `exec -H demo -- curl -d '{"k":"v"}' http://127.0.0.1/api`；一个参数仍是远端 shell 脚本。Git Bash 可能把 `/etc/nginx` 改写成 `D:/.../etc/nginx`，看到警告后改用 `//etc/nginx` 或 `MSYS_NO_PATHCONV=1`。`docker restart` 的确认也覆盖 `stop`、`start` 和 `kill`，不要拆成 stop 再 start 来绕过。详情在 `SKILL.md` 和[使用参考](usage.md)。

之后可以试这些明确的请求：

- “查看 demo 最近的操作记录，说明有没有失败；不要重跑命令。”
- “先检查 demo 上 nginx 的状态，只汇报，不重启。”
- “把本机 ./artifact.jar 上传到 demo 的 /tmp/artifact.jar；遇到覆盖确认先交给我处理。”

Agent 应先确认目标别名，用 JSON 判断成功、失败和不确定结果；被策略拒绝时说明原因，丢失响应时先核验远端状态。**Skill 不替代命令策略、TTY 人工确认或系统权限。**

## 更新与移除

更新仓库后，再运行所选客户端的安装脚本并加显式覆盖选项：

```sh
sh scripts/install-skill.sh claude --force
```

```powershell
.\scripts\install-skill.ps1 -Agent claude -Force
```

项目级安装更新时还要传相同的项目目录。卸载时只移除表中安装的 `ssh-cli` Skill 目录，不要删除 SSH 主机配置或凭据。CLI 和 Skill 分开更新；使用新参数之前，先确认 `ssh-cli version` 和对应命令的 `--help`。

## 没有识别 / 不能执行，检查哪里

| 现象 | 下一步 |
| --- | --- |
| 找不到 Skill | 检查文件名是否是大写 `SKILL.md`、父目录是否叫 `ssh-cli`，以及是否装在当前客户端扫描的位置；重新打开会话，仍不显示再重启客户端 |
| Copilot CLI 中途安装后看不到 | 在会话里运行 `/skills reload`，再用 `/skills info ssh-cli` 检查位置 |
| 能加载 Skill，但找不到命令 | 安装未完成或运行环境已变化；检查 PATH 和默认安装路径，缺失时安装 CLI 并验证版本后再使用 |
| 找不到已经登记的主机 | 检查运行用户、`SSH_CLI_HOME` / `--config` 和工作环境；不要在聊天中粘贴密码 |
| agent 认证失败 | 在同一环境检查 `ssh-add -l`；有 `agentKey` 时必须能找到对应公钥，不要清空指纹绕过失败 |
| 显示策略拒绝 / 需要人工确认 | 先看 `policy show -H <别名>`；交给用户处理该确认；不要自动改策略、切环境，或把 `restart` 拆成 `stop`/`start` |
| 本地能用，云端不能用 | 个人 Skill、CLI、网络和凭据不自动同步；Cursor 和 Claude 的本地个人目录也不能视为云端已经安装 |

平台安装和发现方式按上面的官方文档核实于 **2026-10-15**。没有原生 Skill 机制的 Agent，可以让它显式读取这份文件作为任务说明，但那是手动加载，不应声称它会自动发现或获得 SSH 能力。
