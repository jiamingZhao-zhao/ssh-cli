# 安装 ssh-cli

发布资产的文件名（版本号不带前导 `v`）：

| 系统 | 文件 | 包内二进制 |
|------|------|------------|
| Linux、macOS | `ssh-cli_<version>_<os>_<arch>.tar.gz` | `ssh-cli` |
| Windows | `ssh-cli_<version>_windows_<arch>.zip` | `ssh-cli.exe` |

`os` 是 `linux`、`darwin`、`windows`；`arch` 是 `amd64` 或 `arm64`。可选的 `checksums.txt` 是 sha256sum 清单。仓库目前还没有 GitHub Release 时，下面的下载命令会失败，可以先用 `go build`。

## Linux / macOS

装到 `~/.local/bin`（可用 `SSH_CLI_BIN` 改目录），不需要 root：

```bash
curl -fsSL https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.sh | sh
```

## Windows

装到 `%LOCALAPPDATA%\ssh-cli\bin`（可用 `SSH_CLI_BIN` 改目录），不需要管理员。目录还不在用户 PATH，也不在系统 PATH 里时，安装脚本会把它追加到**用户** Path，并更新当前窗口的 PATH。已经在其中则不会重复追加。

### 只开 cmd.exe

不启动 PowerShell。Windows 10 及以上自带 `curl.exe` 和 `tar.exe`。下面这一行要在 **cmd.exe** 里执行（PowerShell 不会展开 `%TEMP%`）：

```bat
curl.exe -fsSL -o %TEMP%\ssh-cli-install.cmd https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.cmd && %TEMP%\ssh-cli-install.cmd
```

版本来自 `https://github.com/<仓库>/releases/latest` 的重定向：响应头 `Location` 指向 `/releases/tag/<tag>`。脚本不访问 `api.github.com`，因此不受匿名 API 速率限制影响。下载地址是 `https://github.com/<仓库>/releases/download/<tag>/ssh-cli_<version>_windows_<arch>.zip`（`<version>` 是 tag 去掉一个前导 `v`）。解压只用系统自带的 `tar.exe -xf <zip> -C <目录>`。Windows 的 `tar.exe` 是 bsdtar，不接受 GNU 的 `--force-local`。

固定版本（前导 `v` 可有可无，会按仓库的 `v` 标签去下载）：

```bat
set SSH_CLI_VERSION=0.1.0
curl.exe -fsSL -o %TEMP%\ssh-cli-install.cmd https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.cmd && %TEMP%\ssh-cli-install.cmd
```

读不到重定向时，脚本改用 `0.1.0` 并打印警告。`SSH_CLI_REPO` 可设为 `owner/name`。`PROCESSOR_ARCHITECTURE`（以及 32 位 cmd 里的 `PROCESSOR_ARCHITEW6432`）用来区分 `amd64` 和 `arm64`。

发布里如果有 `checksums.txt`，用 `certutil -hashfile` 做 SHA256 校验；没有则警告后继续。校验和不匹配，或清单里没有这个 zip，会停止安装。

用户 Path 写在 `HKCU\Environment`（保留原来的 `REG_EXPAND_SZ`，不用 `setx`，避免 PATH 超过 1024 字符被截断）。当前这个 cmd 窗口会立刻生效。开始菜单里新开的窗口要注销再登录后才会继承这次写入。

### PowerShell

`install.ps1` 仍可用。它通过 .NET 写入用户 Path，当前会话和新打开的终端都会带上：

```powershell
irm https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.ps1 | iex
```

## 从源码安装

```bash
go install github.com/jiamingZhao-zhao/ssh-cli/cmd/ssh-cli@latest
```

`go install` 不会写入发布版本号，`ssh-cli version` 显示 `ssh-cli dev`。当前仓库直接构建：

```bash
CGO_ENABLED=0 go build -o ssh-cli ./cmd/ssh-cli
```

发布包在 CI 里由 `scripts/package.sh` 打出来，并用 ldflags 写入版本、提交和日期。

## 装好之后

```bash
ssh-cli -h
ssh-cli version
ssh-cli update --check
```

`ssh-cli update` 只会在你执行这条命令时替换当前二进制，不会在后台自行更新。没有交互终端时它拒绝安装（退出码 253）；`--check` 只查询。
