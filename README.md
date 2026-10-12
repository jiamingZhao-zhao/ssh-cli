# ssh-cli

零依赖的单文件 SSH 运维 CLI（Go）。远程命令、文件上传下载；凭据加密存储，危险命令拦截，对 agent 友好的输出。

当前包含第 1 次迭代（M0 + M1，以及策略引擎核心）、第 2 次迭代（版本号、`update`、安装脚本）、强制审计日志和可选的本机 UI，以及 0.3.0 的配置面打通、`import ssh-ops`、`status` / `service` / `keys`。0.3.1 让 `--timeout` 限制 SSH 建连，并为分组增加可选显示名。0.3.2 让 `update --yes` 在没有交互终端时也能安装。0.3.3 起，不带参数的 `ssh-cli update` 在没有交互终端时也会安装。0.4.0 增加进程内会话、审计分页与 30 天清理、不含明文的配置导入导出、本机 UI 执行和上传下载、轻量 relay，以及策略 HMAC。0.5.0 用内嵌的 Tabler 组件和 Alpine.js CSP 重排本机界面，并加上概览、主机详情、会话倒计时、审计筛选与 CSV、运维向导、深色与紧凑表格、批量并行执行和设置页。本机页面另有交互终端：有效模式为 standard 或 admin 时不逐条套用命令策略，审计来源记为 `ui`，不记录按键；有效模式为 readonly（含 prod）时拒绝无限制终端，浏览器请求头不算人工身份。0.7.10 起，本机页面的文件变更、上传和下载即使请求带上浏览器头也走能力检查；执行、上传、下载、文件变更、列目录、历史和概况都会写入审计，`source` 为 `ui`。历史在 `noDataOutflow` 下默认不带回正文。0.7.11 起，`exec -c` / `-l` / `-a` 按内层命令分类，还原不了就拒绝放行；`ss` 的 `-K` / `--kill` 与 `-D` / `--diag` 在 readonly 和 standard 下拒绝；重命名同时检查源路径和目标路径，递归删除与受保护子路径相交时要确认。0.7.12 起，SSH 连接（含跳板）大约每 30 秒做一次 keepalive，45 秒没有应答就关掉这条连接，终端和共用它的概况、文件面板不会再静默挂死。交互终端的 WebSocket 大约每 30 秒 ping，90 秒读不到任何帧就清理。会话到达最长寿命时，终端先写出「会话已达到最长时限，连接已关闭」，页面同时显示横幅和提示。0.7.13 起，跳板后的 SSH 握手在超时或取消时会关掉这一跳；修改跳板的地址、端口、用户、认证或身份文件会让依赖它的目标会话失效。终端 WebSocket 的写入和关闭有期限，关不掉就直接断开底层连接。批量执行按退出码和 status 显示失败数量。HMAC 文案和颜色使用同一个状态。审计 CSV 导出全部匹配记录，不再在 2000 条处静默截断。发布版本号仍由 tag 经 ldflags 注入，源码里的 `Version` 保持 `dev`。破窗提权（elevate）、GoReleaser 和 SKILL.md 还没做。设计全文见 [docs/PLAN.md](docs/PLAN.md)。安装步骤见 [INSTALL.md](INSTALL.md)。

0.7.15 改进本机工作台的刷新、断线提示、目录记忆、小屏布局和弹窗键盘操作。批量执行增加无连接预检、操作去重与结果查询；上传在确认覆盖后以临时文件完成替换，并收紧路径和取消处理。没有新增运行时依赖或前端构建步骤。行为边界与 API 示例见 [0.7.15 版本说明](docs/releases/v0.7.15.md)。

0.7.16 修正本机工作区：文件表恢复只有横线的表格，进程命令列不再被挤成 `/..`，传输队列移到左侧底部，并去掉概况里的「主机 / 进程 / 网络」标题和网络图。目录树从 `/` 展开，名称只显示最后一段。下载和上传走与命令行相同的 SFTP，页面只显示进度；不再把文件整段放进浏览器内存，也不再设 128 MiB / 63 MiB 的网页上限。见 [0.7.16 版本说明](docs/releases/v0.7.16.md)。

0.7.17 把磁盘用量挪到交换下面，和内存一样显示「百分比 · 已用 / 全部」，挂载点与进度条同一行。进程表只留内存占用最高的 5 条，命令列只显示短名称，完整启动命令在该行的「详情」里。下载和上传在传输队列里显示百分比、字节和与 CPU 相同的进度条。连接状态从终端标签处移到终端和文件区之间的分隔条。见 [0.7.17 版本说明](docs/releases/v0.7.17.md)。

0.7.18 只调整本机工作区的排布。进程表的内存、CPU、命令与表头居中对齐，表格贴齐左栏。磁盘改成和内存、交换相同的两行：上一行是「磁盘」加挂载点和「百分比 · 已用 / 全部」，下一行是整宽进度条。传输队列上移到概况下面，保存位置用系统目录选择器，不手填路径；没有传输时是空状态，没有可清除的记录时不显示「清除已完成」。连接状态改到「文件 / 历史」那一行。未连接时文件和历史内容区留白。终端标签贴着打开按钮那一栏。见 [0.7.18 版本说明](docs/releases/v0.7.18.md)。

0.7.19 修正目录选择、传输队列、进程条数、终端标签和磁盘。选择下载目录改为 POST JSON。传输队列与「文件 / 历史」同一行；没有传输时只显示小字「传输队列」和虚线框。进程表和概况接口都只保留内存占用最高的 7 条。终端标签与主机选择在同一行。磁盘挂载点去掉末尾 `/`，只显示根分区 `/` 的一条用量。见 [0.7.19 版本说明](docs/releases/v0.7.19.md)。

0.7.20 把概况进程改回内存占用最高的 5 条，页面和接口一致。没连接时进程表仍固定 5 行空位，左栏不收起；「传输队列」和保存目录钉在左下角，点保存目录仍用 JSON 选择文件夹，点已完成的下载会打开所在目录。有数据的进程行本身可点，打开原来的详情，不再单独放「详情」链接。见 [0.7.20 版本说明](docs/releases/v0.7.20.md)。

## 构建

需要 Go 1.26+。发布和 CI 使用 Go 1.27。六个目标平台都用 `CGO_ENABLED=0`：

```bash
CGO_ENABLED=0 go build -o ssh-cli ./cmd/ssh-cli
```

交叉编译示例：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ssh-cli ./cmd/ssh-cli
```

本地构建的版本号是 `dev`。`0.3.1` 这类补丁号不写进源码，打 tag `v0.3.1` 时由 `scripts/package.sh` 用 ldflags 写入。发布包同样写入提交和日期：

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

`version`、`--version`、`-V`、`-version` 打印同一行。`update` 从 GitHub Release 下载当前平台的资产并替换正在运行的二进制，只在执行该命令时发生。最新版本来自 `https://github.com/<仓库>/releases/latest` 的重定向，资产和 `checksums.txt` 从 `releases/download/<tag>/` 直接下载，不访问 `api.github.com`，因此不受匿名 API 速率限制影响。只有在这次直接解析失败、并且环境里设置了 `GITHUB_TOKEN` 时，才会回退到 Releases API。没有 `checksums.txt` 时会警告并继续；校验和不匹配则拒绝安装。有交互终端时要输入发布版本号确认，`--yes` 跳过这次确认。自 0.3.3 起，没有 TTY（Windows cmd、PowerShell、agent 控制的 shell）时直接安装，不必加 `--yes`，写了也不会报错。`--check` 只查询。仓库和资产名见 [INSTALL.md](INSTALL.md)。

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

ssh-cli exec -H main --timeout 30s -- "df -h /"
ssh-cli exec -H a -H b --parallel 2 -- "uptime"
ssh-cli exec -H main --script ./status.sh
ssh-cli upload -H main ./dist //root/app/dist
ssh-cli download -H main /var/log/app.log ./app.log

ssh-cli policy show -H main
ssh-cli policy explain -H main -- "systemctl restart nginx"
```

`//root/...` 会还原成 `/root/...`，用来避开 Git Bash 对绝对路径的改写。

`--timeout` 同时约束两段时间，彼此分开计时：SSH 建连，以及连上之后的命令。没写 `--timeout` 时建连仍是 20 秒。写了更短的时间（例如 `3s`、`8s`）时，连不上的主机会在这段时间内失败，而不会固定等到大约 20 秒。比 20 秒更长的 `--timeout` 只加长命令本身，建连仍在 20 秒内结束。`status`、`service`、`keys` 的 `--timeout` 同样限制建连。

内置命名策略 `readonly`、`standard`、`admin` 可直接引用，也可以在 `hosts.yaml` 里用同名条目覆盖。`policy add` / `policy edit` / `policy remove` 和本机 UI 写同一份 `hosts.yaml`。`policy sign` 用主密钥写 `policy.mac`。签名覆盖策略，也覆盖每台主机的地址、端口、用户和认证方式。还没签过名、也没有 `policy.mac` 时，仍按旧配置加载。签过名之后 `hosts.yaml` 里会有 `policySigned: true`，这时删掉 `policy.mac` 会拒绝加载，要用 `policy unsign` 才回到未签名。旧的 v1 `policy.mac` 不含连接信息，需要重新 `policy sign`。有文件但不符则拒绝加载。HMAC 不代替人工确认。

## 权限怎么算

一台主机的有效权限是各层允许集合的交集，再减去各层拒绝的并集（含不可关闭的内置硬拒绝）：

- 某一层没写 `allow`，这一层是全集，不把别的层交空。
- 模式 `readonly ⊂ standard ⊂ admin`。环境的 `maxMode` 是天花板，分组写成 `admin` 也不会超过它。
- `confirm` 取并集。确认必须在交互终端里输入主机别名。没有 TTY（包括 agent）直接拒绝，退出码 253。`--yes` 只在有 TTY 时有效。
- 只读 / 标准模式下，解析不了的命令：只读拒绝，标准视为需确认。`curl|bash`、`base64 -d|sh`、`eval`、`source <(...)` 在这两种模式下拒绝。
- 命令用 `mvdan.cc/sh` 解析，`;`、`&&`、管道、`$( )`、`sudo`、`bash -c`、`xargs`、`nohup`、`timeout`、`nice`、`stdbuf` 都会展开后再检查。`flock`、`ionice`、`chrt`、`taskset`、`setsid`、`watch` 以及带 `-exec` 的 `find` 展不开：只读拒绝，标准和 admin 需要确认。
- 多台主机先整体预检，有一台被拒绝就整批取消；`--skip-denied` 改为跳过被拒绝的主机。`exec --parallel N` 同时跑 N 台（1 到 4，默认 1）。大于 1 时最多 16 台，和本机页面的批量执行一样。包含 `prod` 且多于一台时仍整批只读。
- 一次选择跨了多个环境，必须加 `--allow-cross-env`。选择里包含 `prod` 且多于一台时，整批强制只读。

主机必须属于且只属于一个分组，环境从分组继承，主机上不能写 `env`。`tags` 只用于 `-t` 选择，分组没有 `tags` 字段。

`host add` / `host edit` 可以用 `--via <别名>` 指定一台已经登记的跳板。连接是「本机 → 跳板 → 目标」：跳板只转发 TCP，不在跳板上开 shell。交互终端、`exec`、上传下载、`ls`、`history` 和概况都跑在目标主机上。别名、地址和审计里的 host 也是目标。页面上跳板只作为一行小字「经由 …」。跳板必须已存在，不能指向自己，链最长 8 台，环会在保存时拒绝。改 `--via`，或改跳板的地址、端口、用户、认证和身份文件，都会让依赖这条路线的目标会话失效。没写 `via` 的主机仍是直连，拨号路径和以前一样。`--clear-via` 改回直连。页面上的「跨机拷贝」是另一件事：把文件经本机从一台拷到另一台，命令仍是 `ssh-cli relay`。

## 环境标签

每次读取配置都会带上四个内置环境。它们的显示名、颜色、`maxMode` 和 `defaultPolicy` 不能改，也不能删除。文件里如果缺了，或者这四项被改过，加载时会改回下表。环境上另外保存的 `breakGlass`、`noDataOutflow` 会留下。

`noDataOutflow: true` 表示这个环境的数据不能回到本机。下载和跨环境中继直接拒绝。`exec` 和 `session run` 仍然执行命令并返回退出码，但丢弃 stdout 和 stderr，终端和 JSON 里只有一行 `noDataOutflow: command output discarded`。要看输出，加上 `--allow-outflow`，并在交互终端输入 `outflow`（`--yes` 只在有 TTY 时有效）。本机 UI 勾选「允许带回命令输出」后，确认短语同样是 `outflow`。这条开关不放行下载。

| 名称 | 显示名 | 颜色 | maxMode | 默认策略 |
|------|--------|------|---------|----------|
| `dev` | 开发 | green | admin | standard |
| `test` | 测试 | yellow | standard | standard |
| `preprod` | 预生产 | orange | standard | standard |
| `prod` | 生产 | red | readonly | readonly |

分组可以挂到任何一个环境，包括内置的，例如 `ssh-cli group add hunan-prod --env prod`。

分组可以另有显示名，和环境下的显示名一样，用来在 `group list` 和连接横幅里显示中文。标识仍是分组 id。本机 UI 的分组表单写同一个 `label` 字段。

```bash
ssh-cli group add hunan-test --env test --label 湖南组测试主机组
ssh-cli group edit hunan-test --label 湖南组测试主机组
```

连接横幅形如 `[测试] box group=hunan-test [湖南组测试主机组]`。`--label ""` 去掉显示名。

自定义环境可以加、改、删。名字不能是上面四个。还被分组使用的自定义环境不能删。

```bash
ssh-cli env add lab --label 实验 --color green --max-mode admin --default-policy standard
ssh-cli env remove lab
```

`env add prod` 和 `env remove prod` 都会拒绝。

## 导入

`import ssh-ops` 只读本地 YAML 或 JSON，不会去连清单里的主机。密码加密进 `secrets.json`，不写进 `hosts.yaml`。格式写在命令帮助里：

```bash
ssh-cli import ssh-ops --help
ssh-cli import ssh-ops --dry-run ./servers.yaml
ssh-cli import ssh-ops ./servers.yaml
```

导入成功后会提示删掉仍含明文密码的清单。

## 状态、服务、公钥

这三个命令用和 `exec` 一样的 `-H` / `-g` / `-t` / `--env` 选择，并且走同一套策略检查。成功、失败和被拒绝都会追加审计 JSONL。

```bash
ssh-cli status -H main
ssh-cli service -H main status nginx
ssh-cli service -H main restart nginx
ssh-cli keys -H main --path .ssh/authorized_keys
ssh-cli keys known list
ssh-cli keys known remove 192.0.2.10:22
```

`status` 做连通性和一组固定的只读检查（主机名、负载、内存、磁盘、监听端口）。`service` 只是 `systemctl <action> <name>`，动作限于 `status` / `start` / `stop` / `restart` / `reload`，服务名有字面量限制；只读策略默认只允许 `status`，`restart` / `stop` 仍按确认规则处理。`keys` 打印远端 `authorized_keys` 的 SHA256 指纹。`keys known` 查看或删除本机 `known_hosts`：删掉一条之后，下次连接会记下看到的第一把钥匙；还留在文件里的钥匙如果变了，仍然拒绝。

## 远程目录与 shell 历史

`ls` 和 `history` 用和 `exec` 一样的主机选择与策略。成功、失败和被拒绝都写入审计。命令行的 `source` 为 `cli`，本机页面为 `ui`。请求体里自报 `source=ui` 不能跳过策略。页面只在监听回环时可以不逐条套用历史命令的文本策略；`noDataOutflow` 仍会抑制正文，确认短语仍是 `outflow`。列目录在 `noDataOutflow` 下直接拒绝。

```bash
ssh-cli ls -H main
ssh-cli ls -H main /var/log
ssh-cli history -H main
ssh-cli history -H main --lines 50 --json
```

`ls` 通过 SFTP 读一个目录，默认是登录目录，最多 2000 项。它不创建、不改名、不删除。策略要允许 `ls`。`noDataOutflow` 会拒绝列目录，和下载一样。

`history` 只读远端用户的 shell 历史，不会写入或截断历史文件。它先 `cat` 常见 rc（`~/.bashrc`、`~/.bash_profile`、`~/.profile`、`~/.zshrc`、`~/.zprofile`、`~/.zshenv`、`~/.config/fish/config.fish`）查找静态的 `HISTFILE`。找不到、或值里有 `$` / 反引号时，再按顺序试：

- `~/.bash_history`（bash）
- `~/.zsh_history`（zsh，`: 时间:耗时;命令` 会去掉时间戳）
- `~/.local/share/fish/fish_history`（fish，只取 `- cmd:` 行）

默认保留最后 100 条命令，`--lines` 最大 500，正文最多 64KiB。文件不存在时结果是 `empty`；权限不足或路径是目录时是 `unreadable`。两种情况都正常退出，不让界面或命令崩溃。`noDataOutflow` 默认不带回命令文本，需要 `--allow-outflow` 并确认 `outflow`。

历史里和审计日志同一套打码：`password=` / `token=`、PEM 私钥、常见 `--token` 一类参数、URL 里的用户信息。`-psecret` 这种短参数认不出。历史文件本身就可能含密钥。bash 的 `#时间戳` 行会丢掉。多行命令和其他 shell 不会重组。

本机 UI 的终端页是三栏：左侧当前标签的主机概况（地址、运行时间、负载、CPU、内存、交换、根分区磁盘、内存占用最高的 5 个进程；未连接时仍是固定的 5 行空表），传输队列钉在左栏底部，旁边是保存目录，上方是多标签终端（标签与主机选择同一行），下方是文件列表。磁盘只显示根分区 `/`，挂载点去掉末尾的 `/`；和内存、交换一样，上一行是名称和已用/全部，下一行是整宽进度条。进程表的命令列是短名称，点该行打开详情，表头和单元格居中。连接状态在「文件 / 历史」那一行。目录树始终从 `/` 展开，每一级只显示目录名。下载由本机进程调用和 `ssh-cli download` 相同的 SFTP，写到本机目录（默认 `~/Downloads`，否则 `~/ssh-cli-downloads`，也可在队列里用系统目录选择器选定绝对路径）。上传仍把浏览器给出的文件落到临时文件，再调用和 `ssh-cli upload` 相同的 SFTP。页面只显示进度和结果路径。文件和历史上是同一块区域里的两个入口，没有「命令」标签；还没连接时这两块内容区留白。概况是尽力而为：只监听回环时，页面不逐条套用这些固定命令的文本策略；`--allow-non-loopback` 或其他来源仍按允许列表拦截。远端没有 `/proc` 或 `free`/`df`/`ps` 时，缺的项留空并记一条说明，终端照常开。没有端口转发。

## 审计

每次 `exec`、`upload`、`download` 都会在配置目录追加一条 JSONL，命令行和本机 UI 都写。文件变更（`file_change`）、列目录（`list`）、历史（`history`）和概况（`metrics`，含该行详情）同样追加。策略预检拒绝（内置危险命令、确认类命令、能力开关）、超时、认证失败、连接失败，以及远程非零退出都会留下。不记录密码、私钥或明文密钥；命令里的 `password=...` 一类片段会打成 `[redacted]`。历史正文不写入摘要。

记录字段：`time`（本地时区的 RFC3339；本机页面显示为 `yyyy-MM-dd HH:mm:ss`）、`op`（`exec` / `upload` / `download` / `file_change` / `list` / `history` / `metrics` / `relay` / `policy_check` / `session` / `terminal` / `config_change` 等）、主机别名、分组、环境、命令或 `src`/`dst`、`duration_ms`、`exit_code`、截断到 8KiB 的 `result_summary`、`status`（`ok` / `denied` / `timeout` / `auth` / `connect` / `error`）、`high_risk`、`denied_by_policy`、`reason`、`actor`、`source`（`cli` 或 `ui`）。`actor` 取环境变量 `SSH_CLI_ACTOR`，否则是 `cli`；本机 UI 写 `ui`。`source` 由进程填写，请求里自报的来源不算数。交互终端只记开关和字节数，不记按键内容。

```bash
ssh-cli audit list --host main --since 24h --status denied --op exec --source cli --page 1
ssh-cli audit stats
ssh-cli audit cleanup
ssh-cli audit show <id>
ssh-cli audit tail -n 20
ssh-cli audit tail --follow
```

`audit cleanup` 只删除早于 30 天的记录，更近的会拒绝。清理按文件流式处理。

`--host`、`--group`、`--env`、`--json` 是全局参数。`--since` / `--until` 接受 RFC3339、`YYYY-MM-DD`（直到某天包含那一整天）或 `24h` 这种时长。读取是按天顺序扫描，超出时间窗口的文件会直接跳过。

## 本地界面（可选）

0.5.0 的页面用内嵌的 Tabler 和 Alpine.js CSP 版。样式和脚本打进二进制，不跑 npm，断网也能打开。脚本仍限制在 `default-src 'self'`，没有 `unsafe-eval`。xterm 和日期选择器会插入 style 标签，所以样式额外允许 `'unsafe-inline'`。Tabler 的选择框和勾选用 `data:` 图片，所以图片额外允许 `data:`。Alpine 只把按钮、表单和表格接到原来的 JSON 接口。导航、卡片、表格、对话框、表单、徽章、提示、分页和空状态都用 Tabler 自带的组件。

左侧栏切换：概览、终端、主机、主机详情、分组、标签、环境、危险命令、已知主机密钥、审计、跨机拷贝、运维、设置。会话和执行不在主导航里。列表默认每页 10 条，可改成 20 或 50。在主机页按 `/` 聚焦搜索。深色用 `data-bs-theme`，紧凑表格用 Tabler 的 `table-sm`。长命令和路径截断，点开看全文。审计日期用日历选择，也可以点 1 小时、24 小时、7 天或 30 天。页面上的时间都是 `yyyy-MM-dd HH:mm:ss`。内置环境 `dev`、`test`、`preprod`、`prod` 只读。不运行就等于关闭，没有后台进程。添加和编辑用居中对话框。导入清单仍用 `import ssh-ops`。配置包用 `config export` / `config import`，不含明文密码。批量执行在页面上对应 `POST /api/exec/batch`，在命令行上对应 `exec --parallel`。

```bash
ssh-cli ui
ssh-cli ui --addr 127.0.0.1:7788
```

打开 <http://127.0.0.1:7788> 之后：

- **概览**：主机数、最近命令、最近失败，以及策略 HMAC 是否有效。近 14 天画成柱状图，操作类型画成环形图。
- **主机**和**主机详情**：勾选多台后可以批量执行，一次最多 16 台，并行最多 4。包含 `prod` 且多于一台时，整批按只读策略检查。详情页给出分组、环境、标签、有效策略、当前会话和这台主机最近的审计。
- **分组**：新建、修改环境、命名策略、行内 allow/deny/confirm 和受保护路径。有主机的分组不能删，和 `group remove` 一样。
- **标签**：标签只在主机上，给 `ssh-cli -t` 选择用，分组没有 `tags` 字段。可以把一个标签加到该分组下的每台主机，或从全组去掉。
- **危险命令**：用表单编辑 allow / deny / confirm，不手改 JSON。内置环境只读；自定义环境可以改 `maxMode` 和 `defaultPolicy`。某一层不写 allow 就是全集，写成空列表则会把这一层交空。内置硬拒绝不能关。HMAC 仍由 `policy sign` 维护。
- **审计**：按操作、来源（`cli` / `ui`）、主机、分组、环境、状态和时间筛选，表头可以再过滤当前页，失败行用危险色和警告色。可以导出全部匹配的 CSV，不再在 2000 条处截断。清理只删 30 天前的记录。
- **会话**：列出状态、空闲倒计时和最长寿命，可以打开或关闭。会话只活在这个 UI 进程里。
- **跨机拷贝**和**运维**：跨机拷贝对应命令行 `relay`，把远端文件经本机转到另一台并核对校验和。密码只通过主机表单 POST 进加密存储，不会回显，也不会写入审计。运维页分步导出、导入、查看 HMAC、清理审计。配置包不含明文。
- **终端**是日常操作页：左侧主机概况，上方多标签终端，下方文件。文件区可以拖入本机文件（可多选，有进度和取消），双击进入目录，右键上传、下载、刷新、复制路径。把远端文件拖到左侧传输队列时，本机进程用和命令行相同的 SFTP 写到保存目录，不经过浏览器内存。没有「命令」标签，也没有端口转发。有效模式为 standard 或 admin 时，交互终端不逐条套用命令策略，只把打开和关闭记入审计，不记录按键。readonly（含 prod）拒绝无限制终端，伪造的 Origin、Sec-Fetch 或 CSRF 不能把它打开。文件变更、上传和下载始终走能力检查：只读环境不能改远端文件。重命名会检查源路径和目标路径，删除会检查整棵目录里有没有受保护路径；碰到受保护路径要确认主机别名。`noDataOutflow` 拒绝下载。列目录在 `noDataOutflow` 下拒绝。只监听回环时，历史和概况可以不逐条套用命令文本策略；历史仍服从 `noDataOutflow`，默认不带回命令文本，要带回须确认 `outflow`。这些操作都写入审计，`source` 为 `ui`。命令行仍然拦截并审计。连接状态（空闲剩余、最长剩余）和连接 / 断开在终端页上。会话到达最长寿命时，终端里会先写出「会话已达到最长时限，连接已关闭」，并在页面上显示横幅和提示。分隔条宽度会记在这台浏览器里。概况和历史读不到时只显示说明。
- **审计**默认只看 `source=cli`。概览上的条数和近 14 天图也只数命令行。页面操作（终端开关、执行、文件、历史、概况）把来源改成「全部」或 `ui` 才能看见，不进默认统计。记录本身都在。
- **执行**和**会话**不再放在主导航。同样的事在终端页完成。运维页留了高级入口；执行接口还在，仍套用策略，并记入审计（`source=ui`）。
- **设置**：默认命令超时、每页条数、主题、密度，以及跨机拷贝是否默认允许跨环境，保存在这台浏览器。会话空闲和最长寿命写入 `hosts.yaml`，和命令行共用。

连接失败、策略拒绝和空列表会写出下一步该做什么。

执行、上传、下载、跨机拷贝、会话、审计清理和配置导入导出都在本机页面里。上传、下载、文件变更和执行的策略与命令行相同，并写入审计。standard 和 admin 的交互终端不逐条套用命令策略；readonly 没有无限制终端。只监听回环时，概况和历史可以不逐条套用命令文本策略，外流限制仍然有效。elevate 仍不做。跳板不提供端口转发界面；它只在连接目标主机时使用。

默认只监听 `127.0.0.1:7788`。`0.0.0.0` 和其他非回环地址会拒绝，除非显式加上 `--allow-non-loopback`。该模式启动时打印一次随机 Bearer token。之后每个 `/api` 请求都要带 `Authorization: Bearer <token>`。页面会提示粘贴这个 token。`Host: localhost` 不能代替它。这个模式下概况、进程行详情和历史也不再豁免命令文本策略，伪造的浏览器头不能放宽只读探测；审计仍全部写入。更稳妥的做法是 SSH 隧道到 `127.0.0.1`，不要把端口暴露到公网。用 Ctrl-C 停止。

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

## 会话、跨机拷贝、配置包

```bash
ssh-cli session run -H box --command 'cd /tmp' --command pwd
ssh-cli relay --from left:/tmp/a --to right:/tmp/b
ssh-cli config export -o bundle.yaml
ssh-cli config import bundle.yaml
ssh-cli policy sign
```

`session run` 在同一个进程里复用一个 shell，命令结束后关闭。空闲默认 5 分钟，最长 60 分钟，忙着也会到点关闭；本机终端会先写出提示，并在页面上显示横幅。连接大约每 30 秒发送 SSH keepalive，对端没有应答就关闭，避免空闲或半开连接把终端和旁边的概况、文件面板挂死。另开一个进程看不到这些会话。UI 进程是会话的持有者。`relay` 只经本机转发一个文件，并用远端 `sha256sum`（否则 `md5sum`）核对。配置包保存主机、策略和密钥引用，不写密码明文，也不改 `secrets.json`。

## 这次没做

`elevate`（破窗提权）、GoReleaser、SKILL.md。打 `v*` tag 时 Release 工作流会发布六个平台压缩包和 `checksums.txt`。
