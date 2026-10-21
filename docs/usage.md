# 使用与配置参考

[返回中文首页](../README.md) · [English overview](../README.en.md) · [Agent Skill 指南](skills.md)

这里保留详细的配置、策略和命令说明。新用户先看首页；最新边界以命令帮助和[版本说明](releases/README.md)为准。

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

`install.ps1` 仍然可用。两者都默认装到 `%LOCALAPPDATA%\ssh-cli\bin`，目录不在 PATH 里时写入用户 Path。详见 [安装说明](../INSTALL.md)。

`version`、`--version`、`-V`、`-version` 打印同一行。`update` 从 GitHub Release 下载当前平台的资产并替换正在运行的二进制，只在执行该命令时发生。最新版本来自 `https://github.com/<仓库>/releases/latest` 的重定向，资产和 `checksums.txt` 从 `releases/download/<tag>/` 直接下载，不访问 `api.github.com`，因此不受匿名 API 速率限制影响。只有在这次直接解析失败、并且环境里设置了 `GITHUB_TOKEN` 时，才会回退到 Releases API。没有 `checksums.txt` 时默认拒绝安装；显式 `--allow-missing-checksum` 才允许缺失清单，校验和不匹配仍拒绝安装。有交互终端时要输入发布版本号确认，`--yes` 跳过这次确认。自 0.3.3 起，没有 TTY（Windows cmd、PowerShell、agent 控制的 shell）时直接安装，不必加 `--yes`，写了也不会报错。`--check` 只查询。仓库和资产名见 [安装说明](../INSTALL.md)。

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
ssh-cli upload -H main ./app.conf /etc/app.conf --backup --json
ssh-cli download -H main /var/log/app.log ./app.log

ssh-cli policy show -H main
ssh-cli policy explain -H main -- "systemctl restart nginx"
ssh-cli policy dangerous
ssh-cli policy dangerous set --enable --rule rm-root
```

`//root/...` 会还原成 `/root/...`，用来避开 Git Bash 对绝对路径的改写。Git Bash 还可能在程序看到参数之前，把 `/etc/nginx` 改写成 `D:/soft/git/Git/etc/nginx` 这种带盘符的路径。`exec`、`upload`、`download` 和 `ls` 发现这种形状会在 stderr 警告，并在 `--json` 里加上 `warnings`；命令不会改写该参数。处理办法是写成 `//etc/nginx`，或在这一条命令前加上 `MSYS_NO_PATHCONV=1`。PowerShell 和 cmd 没有这层转换。

## exec 怎么把参数送到远端

远端登录 shell 只会解析一次 ssh-cli 送出的命令字符串。

- **一个参数**是远端 shell 脚本，原样送出。管道、重定向和你写在这串字符串里的引号仍是 shell 语法：`ssh-cli exec -H main -- "df -h / | head"`。
- **两个及以上参数**是 argv。含空格、引号或其它 shell 元字符的参数会按 POSIX 单引号包起来再拼接。远端 shell 解析这一次后，按还原出的 argv 执行，参数内部不会再被解析。因此 `ssh-cli exec -H main -- sh -c 'mkdir -p /a /b'` 收到的是完整脚本，`ssh-cli exec -H main -- curl -d '{"k":"v"}' http://127.0.0.1/api` 收到的 JSON 仍带引号。
- 全是普通字面量的参数保持原样，`ssh-cli exec -H main -- systemctl status nginx` 送出的仍是 `systemctl status nginx`。
- `--forward-stdin` 把本机 stdin 交给这一条远端命令（例如 `crontab -`）。只能一台主机，不能和 `--script`、`--stdin`、`--daemon` 或 `--parallel` 大于 1 一起用。`--script` / `--stdin` 仍然表示脚本正文。

策略检查用的是同一条命令字符串，所以 `policy explain` 看到的和远端将要执行的一致。

## 先看策略，再执行

`ssh-cli policy show -H main` 只读本机 `hosts.yaml`，不连接、不执行。它列出确认门槛（`confirm`）、受保护路径、能力开关，以及环境规则：`maxMode`、`defaultPolicy`、`noDataOutflow`、`breakGlass`。`dangerousCommands` 把建议清单和当前环境真正生效的规则分开：`catalog` 始终在，`enforcedHere` / `active` 才是会拦截的部分。`policy explain` 里 kind 为 `catalog` 的行表示命中了建议规则但没有拦截。`--json` 的 `envRules` 和 `equivalence` 是给 Agent 用的。有 `equivalence` 行时，表示某条 confirm/deny 还会挡住等价操作，例如配置了 `docker restart` 时，`docker stop`、`docker start`、`docker kill` 同样要确认。`docker container restart` 与 `docker restart` 相同。`systemctl restart` 和 `apps.sh restart` 同样覆盖 `stop` 和 `start`。只配置了 `docker stop` 时，会连带 `restart` 和 `kill`，不会连带单独的 `start`。

`./script.sh`、`/path/file.sh`、`sh script.sh`、`source script.sh` 和 `. script.sh` 都是看不到正文的脚本，standard 需要确认，readonly 拒绝。把脚本正文贴进 `sh -c` 会按里面的每条命令检查，不能用来绕过其中已经被拦住的命令。没有 `.sh` 后缀、也没有用 `sh` / `source` 拉起的可执行文件（例如 `./deploy`）不在这组规则里。`docker compose` 也不在这组规则里。

`podman` 只有在策略写了 `podman` 时才套用同一套生命周期规则，不会因为写了 `docker` 就挡住 `podman`。

`--timeout` 同时约束两段时间，彼此分开计时：SSH 建连，以及连上之后的命令。没写 `--timeout` 时建连仍是 20 秒。写了更短的时间（例如 `3s`、`8s`）时，连不上的主机会在这段时间内失败，而不会固定等到大约 20 秒。比 20 秒更长的 `--timeout` 只加长命令本身，建连仍在 20 秒内结束。`status`、`service`、`keys` 的 `--timeout` 同样限制建连。

内置命名策略 `readonly`、`standard`、`admin` 可直接引用，也可以在 `hosts.yaml` 里用同名条目覆盖。`policy add` / `policy edit` / `policy remove` 和本机 UI 写同一份 `hosts.yaml`。`policy sign` 用主密钥写 `policy.mac`。签名覆盖策略、危险命令清单的启用和选中项，也覆盖每台主机的地址、端口、用户和认证方式。还没签过名、也没有 `policy.mac` 时，仍按旧配置加载。签过名之后 `hosts.yaml` 里会有 `policySigned: true`，这时删掉 `policy.mac` 会拒绝加载，要用 `policy unsign` 才回到未签名。旧的 v1 `policy.mac` 不含连接信息，需要重新 `policy sign`。有文件但不符则拒绝加载。HMAC 不代替人工确认。

## 权限怎么算

一台主机的有效权限是各层允许集合的交集，再减去各层拒绝的并集。危险命令清单是建议列表，默认不参与这个并集：

- 某一层没写 `allow`，这一层是全集，不把别的层交空。
- 模式 `readonly ⊂ standard ⊂ admin`。环境的 `maxMode` 是天花板，分组写成 `admin` 也不会超过它。
- `confirm` 取并集。确认必须在交互终端里输入主机别名。没有 TTY（包括 agent）直接拒绝，退出码 253。`--yes` 只在有 TTY 时有效。
- 只读 / 标准模式下，解析不了的命令：只读拒绝，标准视为需确认。`curl|bash`、`base64 -d|sh`、`eval`、`source <(...)` 在这两种模式下拒绝。
- 命令用 `mvdan.cc/sh` 解析，`;`、`&&`、管道、`$( )`、`sudo`、`bash -c`、`xargs`、`nohup`、`timeout`、`nice`、`stdbuf` 都会展开后再检查。`flock`、`ionice`、`chrt`、`taskset`、`setsid`、`watch` 以及带 `-exec` 的 `find` 展不开：只读拒绝，标准和 admin 需要确认。
- 多台主机先整体预检，有一台被拒绝就整批取消；`--skip-denied` 改为跳过被拒绝的主机。`exec --parallel N` 同时跑 N 台（1 到 4，默认 1）。大于 1 时最多 16 台，和本机页面的批量执行一样。包含 `prod` 且多于一台时仍整批只读。
- 一次选择跨了多个环境，必须加 `--allow-cross-env`。选择里包含 `prod` 且多于一台时，整批强制只读。

危险命令清单（删掉文件系统根、`mkfs`、把 `dd` 或重定向写到磁盘设备、对根目录 `chmod`/`chown`、fork bomb）开箱只作为建议。`policy dangerous` 能看到每一条是建议、已选中，还是正在本机环境生效。不执行 `policy dangerous set --enable` 并选中规则（`--rule`、`--all` 或额外的 `--deny`）之前，这些命令不会因为这份清单被拒绝。没写 `--env` 时，生效范围默认只有 `prod`。`dev`、`test`、`preprod` 以及其他环境要写进 `--env` 才会套用。关掉开关会留下已保存的列表，但不再拦截；缩小范围需要在交互终端输入 `dangerous`。

这份清单不代替别的限制。`prod` 的 `maxMode` / `defaultPolicy` 仍是 readonly，不在只读白名单里的命令（包括上面那些）还是会被天花板拒绝。`confirm`、受保护路径、能力开关和审计照旧。内置 `standard` 策略里的 `docker system prune -a` 仍是命名策略的 deny，不是这份默认关闭的清单。`journalctl` 的修改参数、`ss -K` 和分页器的 shell 逃逸仍按模式收紧，admin 不收紧。

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

`status` 做连通性和一组固定的只读检查（主机名、负载、内存、磁盘、监听端口）。这些探测仍是固定的 shell 字符串，不走 `exec` 的多参数 argv 封送。`service` 只是 `systemctl <action> <name>`，动作限于 `status` / `start` / `stop` / `restart` / `reload`，服务名有字面量限制；只读策略默认只允许 `status`，`restart` / `stop` 仍按确认规则处理。标准策略里的 `systemctl restart` 还会让 `systemctl start` 进入确认。`keys` 打印远端 `authorized_keys` 的 SHA256 指纹。`keys known` 查看或删除本机 `known_hosts`：删掉一条之后，下次连接会记下看到的第一把钥匙；还留在文件里的钥匙如果变了，仍然拒绝。

`upload` 默认直接覆盖已有普通文件。`--backup` 会先把原文件复制为 `<路径>.ssh-cli.bak`（同一秒内再次备份会加上 Unix 时间后缀），复制失败则不写入。`--confirm-overwrite` 在覆盖前要求输入主机别名；没有 TTY 时退出 253，原文件保持不变。`--json` 在成功时增加 `bytes`、`durationMs`、`sha256`。`sha256` 是按上传计划顺序拼接的普通文件内容，不含目录名和权限。`backups` 列出这次写出的备份路径。下载的 JSON 形状不变。

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

本机 UI 的终端页是三栏：左侧当前标签的主机概况（地址、运行时间、负载、CPU、内存、交换、根分区磁盘、内存占用最高的 5 个进程；未连接时 CPU、内存、交换、磁盘进度条仍在，数值为「—」、进度条为空，下面仍是固定的 5 行空表），传输队列钉在左栏底部，旁边是保存目录，上方是多标签终端（标签与主机选择同一行），下方是文件列表。磁盘只显示根分区 `/`，挂载点去掉末尾的 `/`；和内存、交换一样，上一行是名称和已用/全部，下一行是整宽进度条。进程表的命令列是短名称，点该行打开详情，表头和单元格居中。连接状态在「文件 / 历史」那一行。目录树始终从 `/` 展开，每一级只显示目录名。下载由本机进程调用和 `ssh-cli download` 相同的 SFTP，写到本机目录（默认 `~/Downloads`，否则 `~/ssh-cli-downloads`，也可在队列里用系统目录选择器选定绝对路径）。上传仍把浏览器给出的文件落到临时文件，再调用和 `ssh-cli upload` 相同的 SFTP。页面只显示进度和结果路径。文件和历史上是同一块区域里的两个入口，没有「命令」标签；还没连接时这两块内容区留白。概况是尽力而为：只监听回环时，页面不逐条套用这些固定命令的文本策略；`--allow-non-loopback` 或其他来源仍按允许列表拦截。远端没有 `/proc` 或 `free`/`df`/`ps` 时，缺的项留空并记一条说明，终端照常开。没有端口转发。

## 审计

每次 `exec`、`upload`、`download` 都会在配置目录追加一条 JSONL，命令行和本机 UI 都写。文件变更（`file_change`）、列目录（`list`）、历史（`history`）和概况（`metrics`，含该行详情）同样追加。策略预检拒绝（已启用的危险命令、确认类命令、能力开关）、超时、认证失败、连接失败，以及远程非零退出都会留下。不记录密码、私钥或明文密钥；命令里的 `password=...` 一类片段会打成 `[redacted]`。历史正文不写入摘要。

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
- **危险命令**：用表单编辑 allow / deny / confirm，不手改 JSON。内置环境只读；自定义环境可以改 `maxMode` 和 `defaultPolicy`。某一层不写 allow 就是全集，写成空列表则会把这一层交空。危险命令清单默认不拦截，启用后默认只作用于生产环境，用 `policy dangerous` 配置。HMAC 仍由 `policy sign` 维护，签名覆盖这份清单。
- **审计**：按操作、来源（`cli` / `ui`）、主机、分组、环境、状态和时间筛选，表头可以再过滤当前页，失败行用危险色和警告色。可以导出全部匹配的 CSV，不再在 2000 条处截断。手动清理只删 30 天前的记录；可选自动保留策略见 [0.7.26 版本说明](releases/v0.7.26.md)。
- **会话**：列出状态、空闲倒计时和最长寿命，可以打开或关闭。这些网页会话活在 UI 进程里；可选 CLI exec 复用由显式启动的 daemon 持有。
- **跨机拷贝**和**运维**：跨机拷贝对应命令行 `relay`，把远端文件经本机转到另一台并核对校验和。密码只通过主机表单 POST 进加密存储，不会回显，也不会写入审计。运维页分步导出、导入、查看 HMAC、清理审计。配置包不含明文。
- **终端**是日常操作页：左侧主机概况，上方多标签终端，下方文件。文件区可以拖入本机文件（可多选，有进度和取消），双击进入目录，右键上传、下载、刷新、复制路径。把远端文件拖到左侧传输队列时，本机进程用和命令行相同的 SFTP 写到保存目录，不经过浏览器内存。没有「命令」标签，也没有端口转发。网页交互终端不受 readonly / standard / admin 命令模式限制，包含 prod 在内的 readonly 主机也可打开；终端内按远端账号权限运行，不逐条检查 allow、deny、confirm 或危险命令规则。只把打开和关闭记入审计，不记录按键。noDataOutflow 仍禁止终端，建立连接仍需本机页面会话、来源与 CSRF 校验，以及绑定会话的一次性票据；这些检查不能证明操作者一定是真人。CLI 和网页「执行」仍执行原有命令策略。文件变更、上传和下载始终走能力检查：只读环境不能改远端文件。重命名会检查源路径和目标路径，删除会检查整棵目录里有没有受保护路径；碰到受保护路径要确认主机别名。`noDataOutflow` 拒绝下载。列目录在 `noDataOutflow` 下拒绝。只监听回环时，历史和概况可以不逐条套用命令文本策略；历史仍服从 `noDataOutflow`，默认不带回命令文本，要带回须确认 `outflow`。这些操作都写入审计，`source` 为 `ui`。命令行仍然拦截并审计。连接状态（空闲剩余、最长剩余）和连接 / 断开在终端页上。会话到达最长寿命时，终端里会先写出「会话已达到最长时限，连接已关闭」，并在页面上显示横幅和提示。分隔条宽度会记在这台浏览器里。概况和历史读不到时只显示说明。
- **审计**默认只看 `source=cli`。概览上的条数和近 14 天图也只数命令行。页面操作（终端开关、执行、文件、历史、概况）把来源改成「全部」或 `ui` 才能看见，不进默认统计。记录本身都在。
- **执行**和**会话**不再放在主导航。同样的事在终端页完成。运维页留了高级入口；执行接口还在，仍套用策略，并记入审计（`source=ui`）。
- **设置**：默认命令超时、每页条数、主题、密度，以及跨机拷贝是否默认允许跨环境，保存在这台浏览器。会话空闲和最长寿命写入 `hosts.yaml`，和命令行共用。

连接失败、策略拒绝和空列表会写出下一步该做什么。

执行、上传、下载、跨机拷贝、会话、审计清理和配置导入导出都在本机页面里。上传、下载、文件变更和执行的策略与命令行相同，并写入审计。交互终端在 readonly、standard 和 admin 下都按远端账号权限运行，不逐条套用命令策略；noDataOutflow 仍禁止终端。只监听回环时，概况和历史可以不逐条套用命令文本策略，外流限制仍然有效。单命令破窗见 [0.7.26 版本说明](releases/v0.7.26.md)。跳板不提供端口转发界面；它只在连接目标主机时使用。

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

`session run` 在同一个进程里复用一个 shell，命令结束后关闭。空闲默认 5 分钟，最长 60 分钟，忙着也会到点关闭；本机终端会先写出提示，并在页面上显示横幅。连接大约每 30 秒发送 SSH keepalive，对端没有应答就关闭，避免空闲或半开连接把终端和旁边的概况、文件面板挂死。另开一个进程看不到这些会话。UI 进程是会话的持有者。普通 `exec` 每次仍是一条新连接，不会自动复用。要复用必须先在另一个终端运行 `ssh-cli daemon serve`，再对字面量命令使用 `exec --daemon`。daemon 不自动启动，不接受需要确认的命令，不执行 `--stdin`、`--script` 或 `--forward-stdin`，也不覆盖文件传输，失败不重试。`relay` 只经本机转发一个文件，并用远端 `sha256sum`（否则 `md5sum`）核对。配置包保存主机、策略和密钥引用，不写密码明文，也不改 `secrets.json`。
