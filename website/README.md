# ssh-cli 产品落地页

独立静态页面，默认中文，支持英文；无构建步骤、第三方依赖、远端字体或统计请求。以 **v0.7.37 / 5ab4e72** 为发布快照，核对日期 **2026-10-22**。更新版本时需核对文案、命令帮助和生成示例，不能只改版本号。

## 预览

在仓库根目录启动静态服务：

```sh
python -m http.server 7331 --bind 127.0.0.1 --directory website
```

打开 `http://127.0.0.1:7331/index.html?lang=zh#agent`。也可直接打开 HTML；剪贴板能力取决于浏览器。目录可原样部署到静态托管，本次不启用发布工作流。

## 页面组织

首屏说明 Agent 的使用场景。主体为一个六步切换面板：**选主机 → 比较双实例日志 → 本机凭据 → 生产策略 → 操作记录 → 连接复用**。每步先给短说明和实例，详细原理、JSON、更多对比默认折叠。人工网页工作台与默认边界也是折叠内容，避免拉长首页。

- `operations.js`：六步面板、中英文、地区／环境／服务联动、说明型主机与日志、审计和连接切换、复制反馈。示例不执行远端操作、不读取配置；地区通过用户的分组／标签组织，不是内置权限层。
- `app.js`：11 个工作台模块、凭据子步骤、策略与确认演示、安装方式、语言和搜索。命令索引首次搜索时加载。
- `index.html`：语义结构、中文静态内容和文档入口。关闭 JavaScript 仍能读主要介绍；交互控件隐藏。
- `tokens.css` / `styles.css`：沿用 Cobalt 配色和本机字体；支持键盘、窄屏、减少动态效果。命令参考另用 `commands.css`。

页面 CSP 禁止连接 API。所有复制按钮只复制原文；失败会显示可手动选择的文本，切换内容不会留下过期的复制成功反馈。

## 示例与内容依据

| 内容 | 依据与限制 |
| --- | --- |
| Agent 选机 | `host list` 只使用 `--env` 筛清单，不消费 `-H/-g/-t`。Agent 再按返回的 group 和 tags 筛选，执行时传明确别名。执行选择器的分组／标签是并集，不能冒充交集。 |
| 双实例日志 | 说明型的两个实例及版本差异，不是真实服务器诊断。JSON 包装主机和执行状态，不把 stdout 自动变成业务对象，也不根据两行日志断言根因。 |
| 密码 | 核对 `internal/secrets`、`internal/sshclient/auth_host.go`、`internal/catalog`。配置只存 passwordRef；ChaCha20-Poly1305 密文与主密钥分别管理。主密钥顺序为系统凭据库、环境变量、本地文件。同账号访问和密钥泄露边界保持可见。 |
| 生产策略 | 核对 `internal/guard` 与 `internal/cli/policy.go`。prod 默认 readonly；危险清单默认关闭，开启且选规则后才生效。standard 的静态脚本调用允许并不代表脚本内部逐条检查。TTY 确认不是身份认证。 |
| 审计 | 核对 `internal/audit`。CLI 命令／文件操作留记录，可选 HMAC 链与签名校验基线；不是不可变存证。密钥泄露或日志与基线共同回滚在本机核验边界之外。 |
| 连接复用 | 核对 CLI daemon 与执行实现。默认仍直连；显式启动 daemon 后由 `exec --daemon` 使用。仅无需确认的 exec，连接须有效，不含传输，不自动回退／重放，无速度倍数承诺。 |
| 人工工作台 | 以 `internal/ui/web` 为准，11 模块顺序为终端／主机／概览／跨机拷贝、环境／危险命令／分组／标签、审计／运维／设置。网页交互终端不逐条检查策略、不审计每次输入，仅记录会话事件。 |

凭据介绍的概念参考 [agent-database-cli](https://github.com/sleepinginsummer/agent-database-cli)，不声称两者使用相同加密实现，也没有密码强度检查承诺。

对照基准是已配置认证的 OpenSSH。别名、密钥、SSH agent、跳板、ControlMaster / ControlPersist 都是已有能力；优势在于把分类、策略、结果和审计接成一套调用流程。更多传输、并发和中断处理差异在复用面板内展开，不能把可选备份说成默认行为或把 unknown 当作未执行。

## 命令参考

`commands.html` 覆盖该版本 **72 个帮助入口**，不计内部 `__complete`。可按用途、参数、命令名和影响筛选；列表每页 8 项，帮助与参数默认折叠，链接保留语言和筛选。首页搜索也能跳转命令。

`command-notes.json` 提供用途和边界，生成完整 `command-data.js` 与首页精简 `command-index.js`：

```sh
python website/tools/command-reference.py --cli /path/to/ssh-cli
python website/tools/command-reference.py --cli /path/to/ssh-cli --check
```

生成器只在临时配置下调用 version / --help，不执行文档示例。所有真实命令必须有补充说明。

## 核验交互数据

策略面板有 2 环境 × 4 命令 × 3 危险规则范围，共 **24 个实际本地解释结果**。用对应版本构建的 CLI 生成或核对：

```sh
python website/tools/policy-examples.py --cli /path/to/ssh-cli --check
```

生成器只创建临时配置并调用 `policy explain`，不登录主机、不执行 exec。

审计面板的完整、修改、删除三种结果由实际审计模块生成：

```sh
go run ./website/tools/audit-examples --check
```

不加 `--check` 重新生成 `audit-examples.js`。工具使用隔离 keyring、临时随机密钥和临时日志，不访问真实系统凭据库，不输出密钥，不改已有审计记录。生成数据不含随机签名，因此可重复核对。

页面与生成工具均位于 Go embed 目录外，CLI 不导入它们；不增加 CLI 二进制资源、Go/npm 依赖。浏览器校验应覆盖中英文、320／375／414／768 和桌面、键盘导航、复制成功／失败／切换竞态、全部策略组合与三种审计结果。
