# ssh-cli 产品落地页

独立静态页面，默认中文，支持英文切换；无需构建工具或第三方运行时依赖。HTML、CSS、JavaScript、图标均在当前目录，不请求 CDN、字体服务、统计服务或 SSH API。

本页基于 **v0.7.31 / 5e52d45** 的实际功能整理，核对日期为 **2026-10-21**。版本徽标是明确的发布快照，不通过后台请求动态冒充最新版。后续迭代时需同时更新版本链接、边界说明和下面的内容来源。

## 本地预览

可直接打开 `index.html`。需要浏览器的完整剪贴板能力时，在仓库根目录启动任意静态 HTTP 服务，例如：

```sh
python -m http.server 7331 --bind 127.0.0.1 --directory website
```

访问 `http://127.0.0.1:7331`。也可将当前目录原样交给 GitHub Pages 或其他静态托管；本次没有启用自动发布工作流或改动线上站点。

## 内容与实现

- `index.html`：中文默认内容、语义结构、安装和安全边界；没有 JavaScript 时仍可阅读主要介绍并打开文档链接。
- `app.js`：中英文文案、11 个菜单的用途、操作步骤、Agent 场景、安装命令、复制反馈与功能／命令搜索。命令索引仅在首次打开搜索时加载，完整帮助数据只在命令参考页加载。
- 策略交互示例：选择 test / prod、三条命令以及三种危险规则范围，联动显示 ALLOW / CONFIRM / DENY、原因、有效模式、退出码与 JSON。18 个结果来自 v0.7.31 的真实 CLI 本地解释，不由浏览器模拟引擎。检查命令本身可复制，但不会自动执行。
- `policy-examples.js`：只包含用文档地址和临时配置生成的输出节选，不含个人配置或凭据。示例额外配置的重启确认规则已明确标注；页面 CSP 禁止 API 请求。
- `tokens.css` / `styles.css`：浅色 Cobalt 工具风格；使用本机字体回退，不下载字体。支持键盘焦点、减少动态效果与窄屏排版。
- 桌面功能标签支持方向键及 Home / End，手机上使用紧凑的功能选择器，避免菜单占满整屏；搜索支持 Ctrl / ⌘ K、方向键、Enter、Esc；原生 dialog 管理焦点，关闭后回到打开位置。
- JavaScript 未启用时保留主要介绍、命令与文档入口，隐藏无法工作的交互控件。
- 剪贴板被浏览器禁止时显示可选中的原文，不假报复制成功。语言偏好存储不可用时仍可切换。

## Agent 对比与内容依据

首页顺序为 **Agent CLI → 调用对比 → 策略示例 → 人工工作台 → 边界与安装**。CLI 是主要入口，UI 用于人工查看与接手。

原有 Agent 场景区改为 6 个可切换对比：看结果、先检查、选机器、传参数、传文件、断线后。桌面左右并排，窄屏上下排列并使用场景选择器；不额外铺开 6 段长内容。按客户任务解释两边怎么用、能得到什么结果、还有什么限制，只提供使用文档入口，不在产品页展示源码或实现依据。以下依据供维护者核对文案。

| 对比项 | 依据 | 不能据此承诺 |
| --- | --- | --- |
| 结果格式 | `internal/cli/exec.go` 的 `execResult` | stdout 自动变成业务对象；completed 等于成功 |
| 策略预检 | `internal/cli/policy.go`、`internal/guard/` | 可以约束绕过 CLI 的直连；取代服务端权限 |
| 目标范围 | `internal/cli/run.go`、`internal/guard/batch.go` | 批量操作是分布式事务；登记信息必然正确 |
| 参数传递 | `internal/cli/exec_quote_test.go`、`docs/usage.md` | 不再需要本地引号；远端没有 shell |
| 上传处理 | `internal/cli/transfer_cmd.go`、`internal/transfer/` | 默认备份；目录整体事务；摘要代表部署成功 |
| 响应中断 | `internal/cli/outcome_test.go` | 能证明未执行；自动安全重试或回滚 |

直接 SSH 的基准是已配置别名与认证的 OpenSSH，不把缺配置或错误引号当作对照。别名、私钥、SSH agent、跳板和 ControlMaster / ControlPersist 都是 OpenSSH 已有能力，不能当成独有优势。调用方也可用脚本、配置和服务器权限补齐流程。对照依据见 [ssh(1)](https://man.openbsd.org/ssh) 与 [ssh_config(5)](https://man.openbsd.org/ssh_config)。示例按 POSIX shell 书写，两边各自配置；页面不执行示例，没有性能倍数或虚构实测结果。

## 工作台功能来源与优先级

菜单以 `internal/ui/web/index.html` 为准。这里按产品讲解顺序组织，不修改工作台原来的菜单顺序。

| 讲解顺序 | 菜单 | 核心价值与依据 |
| --- | --- | --- |
| 日常高频 | 终端、主机、概览、跨机拷贝 | 工作区、认证身份、配置与监控、通过本机进程中继 |
| 目标与边界 | 环境、危险命令、分组、标签 | 环境上限、执行前策略解释、复用配置与核对目标范围 |
| 记录与维护 | 审计、运维、设置 | 回溯结果、配置迁移、浏览器偏好与会话寿命 |

特别核对 `internal/cli/policy.go`、`internal/guard/dangerous.go`、`internal/cli/relay_cmd.go`、`internal/cli/config_cmd.go`、`internal/cli/ui_cmd.go` 和根目录 `SKILL.md`。危险命令默认未启用，prod 只读上限、人工 TTY 确认与本地审计的信任边界均单独说明。

页面位于 Go embed 目录之外，不改变 CLI 二进制或现有工作台资源，也没有增加 Go/npm 依赖。

## 命令参考

打开 `commands.html`。覆盖 v0.7.31 的 **72 个帮助入口**，包括命令组、子命令与 Shell 补全；不计入 Shell 内部的 `__complete` 协议入口。

- 按中文用途、命令名、别名或参数搜索，也可组合功能分类和操作影响筛选。列表每页 8 条，只显示当前所选命令的详情。
- 详情先给用途、语法、示例和适用限制；本地参数、实际继承的通用参数与 CLI 原始帮助默认折叠。原文保留类型、默认值和可重复标记。
- 通过子命令和上级链接继续浏览。复制命令不会执行；复制链接包含语言、搜索、筛选和当前命令，例如 `commands.html?lang=zh&q=session#session-open`。
- 需要人工 TTY 的操作、只在当前进程存在的会话接口均单独标识。`session open/close` 不提供独立 CLI 调用；`policy edit` 原始帮助中的旧 HMAC 表述由补充说明更正。
- 桌面并排浏览，窄屏先收起结果列表，搜索时展开，选择后回到详情。支持 `/`、Ctrl / ⌘ K、方向键与 Enter。
- 首页导航、模块说明与全站搜索提供入口。首页搜索只显示部分匹配，完整参考页可分页查看全部结果。页面关闭 JavaScript 时提供 CLI 帮助和使用参考的替代入口。

内容分为三部分：`command-data.js` 是完整生成数据，`command-index.js` 是首页用的精简索引，`command-notes.json` 是中英文用途、示例和限制补充。生成器要求每个真实命令都有补充说明，发现增删时停止生成，避免漏项。

以该版本构建的 CLI 生成或核对：

```sh
python website/tools/command-reference.py --cli /path/to/ssh-cli
python website/tools/command-reference.py --cli /path/to/ssh-cli --check
```

脚本仅调用 `version` 与隔离临时配置下的 `--help`，不执行文档示例、不连接服务器。更新版本时需同时核对生成脚本中的版本／提交、补充说明、页面版本链接和功能边界。命令行的帮助是参数来源，示例与适用条件仍需结合实现人工审核。

## 复核策略示例

使用 v0.7.31 源码构建的 CLI 运行（本地构建需通过 ldflags 设置版本号为 `0.7.31`）：

```sh
python website/tools/policy-examples.py --cli /path/to/ssh-cli --check
```

脚本只在临时目录创建示例配置并调用 `policy explain`；不会执行 `exec`、登录主机或更改已有配置。不加 `--check` 可重新生成数据，供维护者审核差异。
