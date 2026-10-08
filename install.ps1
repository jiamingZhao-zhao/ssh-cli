# Install the latest ssh-cli release into a user-writable directory.
# Default destination: %LOCALAPPDATA%\ssh-cli\bin (override with SSH_CLI_BIN).
# Default repo: jiamingZhao-zhao/ssh-cli (override with SSH_CLI_REPO=owner/name).
$ErrorActionPreference = 'Stop'

$repo = if ($env:SSH_CLI_REPO) { $env:SSH_CLI_REPO } else { 'jiamingZhao-zhao/ssh-cli' }
$dest = if ($env:SSH_CLI_BIN) { $env:SSH_CLI_BIN } else { Join-Path $env:LOCALAPPDATA 'ssh-cli\bin' }

switch -Regex ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

$headers = @{
    'User-Agent' = 'ssh-cli-install'
    'Accept'     = 'application/vnd.github+json'
}
$rel = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$repo/releases/latest"
$ver = $rel.tag_name.TrimStart('v').TrimStart('V')
$name = "ssh-cli_${ver}_windows_${arch}.zip"
$asset = $rel.assets | Where-Object { $_.name -eq $name } | Select-Object -First 1
if (-not $asset) {
    throw "latest release has no $name"
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ssh-cli-install-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp $name
    Invoke-WebRequest -Headers $headers -Uri $asset.browser_download_url -OutFile $zip

    $sums = $rel.assets | Where-Object { $_.name -eq 'checksums.txt' } | Select-Object -First 1
    if ($sums) {
        $sumFile = Join-Path $tmp 'checksums.txt'
        Invoke-WebRequest -Headers $headers -Uri $sums.browser_download_url -OutFile $sumFile
        $want = $null
        foreach ($line in Get-Content $sumFile) {
            $parts = $line.Trim() -split '\s+'
            if ($parts.Length -lt 2) { continue }
            $fileName = $parts[-1].TrimStart('*')
            if ($fileName -eq $name) {
                $want = $parts[0].ToLower()
                break
            }
        }
        if (-not $want) { throw "checksums.txt has no entry for $name" }
        $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
        if ($want -ne $got) { throw "checksum mismatch for $name" }
    } else {
        Write-Warning 'release has no checksums.txt; the download was not verified'
    }

    $out = Join-Path $tmp 'out'
    Expand-Archive -Path $zip -DestinationPath $out -Force
    $exe = Get-ChildItem -Path $out -Filter 'ssh-cli.exe' -Recurse -File | Select-Object -First 1
    if (-not $exe) { throw 'archive did not contain ssh-cli.exe' }

    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item -Force $exe.FullName (Join-Path $dest 'ssh-cli.exe')
    Write-Output "installed $(Join-Path $dest 'ssh-cli.exe') ($ver)"

    $entries = @($env:PATH -split ';' | ForEach-Object { $_.TrimEnd('\') })
    if ($entries -notcontains $dest.TrimEnd('\')) {
        Write-Output "Add $dest to PATH, then run: ssh-cli version"
    }
} finally {
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp
    }
}
