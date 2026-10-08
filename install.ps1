# Install the latest ssh-cli release into a user-writable directory.
# Default destination: %LOCALAPPDATA%\ssh-cli\bin (override with SSH_CLI_BIN).
# Default repo: jiamingZhao-zhao/ssh-cli (override with SSH_CLI_REPO=owner/name).
# If the destination is not already on PATH, it is appended to the user Path.
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

    # Compare entries case-insensitively and ignore trailing backslashes.
    $destNorm = $dest.Trim().TrimEnd('\')
    $onPath = {
        param([string]$PathValue, [string]$Dir)
        if ([string]::IsNullOrWhiteSpace($PathValue) -or [string]::IsNullOrWhiteSpace($Dir)) { return $false }
        $needle = $Dir.Trim().TrimEnd('\')
        foreach ($entry in ($PathValue -split ';')) {
            $item = $entry.Trim().TrimEnd('\')
            if ($item -and ($item -ieq $needle)) { return $true }
        }
        return $false
    }

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $onUser = & $onPath $userPath $destNorm
    $onMachine = & $onPath $machinePath $destNorm
    $onSession = & $onPath $env:PATH $destNorm

    # New terminals see User + Machine. Skip the user write when either already
    # has this directory so a second install does not append a duplicate.
    $updatedUser = $false
    if (-not $onUser -and -not $onMachine) {
        if ([string]::IsNullOrWhiteSpace($userPath)) {
            $newUserPath = $destNorm
        } else {
            $newUserPath = $userPath.TrimEnd().TrimEnd(';') + ';' + $destNorm
        }
        [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
        $updatedUser = $true
    }
    $updatedSession = $false
    if (-not $onSession) {
        if ([string]::IsNullOrEmpty($env:PATH)) {
            $env:PATH = $destNorm
        } else {
            $env:PATH = $env:PATH.TrimEnd(';') + ';' + $destNorm
        }
        $updatedSession = $true
    }
    if ($updatedUser) {
        Write-Output "Added $destNorm to user PATH. Current session already updated; new terminals pick it up."
    } elseif ($updatedSession) {
        Write-Output "Added $destNorm to the current session PATH. New terminals already include it."
    }
} finally {
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp
    }
}
