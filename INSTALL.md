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

装到 `%LOCALAPPDATA%\ssh-cli\bin`（可用 `SSH_CLI_BIN` 改目录），不需要管理员。目录还不在用户 PATH（也不在系统 PATH）里时，脚本会把它追加到**用户** Path：当前 PowerShell 会话立即生效，新打开的终端也会带上。已经在 PATH 里则不会重复追加。

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
