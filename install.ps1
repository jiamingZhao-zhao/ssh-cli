# Install the latest ssh-cli release into a user-writable directory.
# Default destination: %LOCALAPPDATA%\ssh-cli\bin (override with SSH_CLI_BIN).
# Default repo: jiamingZhao-zhao/ssh-cli (override with SSH_CLI_REPO=owner/name).
# If the destination is not already on PATH, it is appended to the user Path.
# The tag comes from the releases/latest redirect, not api.github.com.
$ErrorActionPreference = 'Stop'

$repo = if ($env:SSH_CLI_REPO) { $env:SSH_CLI_REPO } else { 'jiamingZhao-zhao/ssh-cli' }
$dest = if ($env:SSH_CLI_BIN) { $env:SSH_CLI_BIN } else { Join-Path $env:LOCALAPPDATA 'ssh-cli\bin' }

switch -Regex ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

if ($repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw "invalid repo '$repo' (want owner/name)"
}

# Tag comes from the releases/latest redirect. Do not call api.github.com.
$latestUrl = "https://github.com/$repo/releases/latest"
$req = [System.Net.HttpWebRequest]::Create($latestUrl)
$req.AllowAutoRedirect = $false
$req.UserAgent = 'ssh-cli-install'
$req.Method = 'GET'
$req.Timeout = 60000
$req.Accept = 'text/html'
try {
    $resp = $req.GetResponse()
} catch [System.Net.WebException] {
    $resp = $_.Exception.Response
    if (-not $resp) { throw }
}
try {
    $status = [int]$resp.StatusCode
    $loc = [string]$resp.Headers['Location']
    $tag = $null
    if ($loc -match '/releases/tag/([A-Za-z0-9._+-]+)') {
        $tag = $Matches[1]
    }
    if (-not $tag -and $status -eq 200) {
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $html = $reader.ReadToEnd()
        $reader.Close()
        if ($html -match 'rel="canonical"[^>]*href="[^"]*/releases/tag/([A-Za-z0-9._+-]+)"') {
            $tag = $Matches[1]
        }
    }
} finally {
    $resp.Close()
}
if (-not $tag) {
    throw "could not read the latest release tag (HTTP $status)"
}
$ver = $tag
if ($ver.StartsWith('v') -or $ver.StartsWith('V')) {
    $ver = $ver.Substring(1)
}
if (-not $ver) {
    throw "could not read the latest release tag (HTTP $status)"
}
$name = "ssh-cli_${ver}_windows_${arch}.zip"
$download = "https://github.com/$repo/releases/download/$tag/$name"
$sumUrl = "https://github.com/$repo/releases/download/$tag/checksums.txt"
$headers = @{ 'User-Agent' = 'ssh-cli-install' }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ssh-cli-install-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp $name
    Invoke-WebRequest -Headers $headers -Uri $download -OutFile $zip -UseBasicParsing

    $sumFile = Join-Path $tmp 'checksums.txt'
    $haveSums = $false
    try {
        Invoke-WebRequest -Headers $headers -Uri $sumUrl -OutFile $sumFile -UseBasicParsing
        $haveSums = $true
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code -ne 404) { throw }
        if ($env:SSH_CLI_ALLOW_MISSING_CHECKSUM -eq '1') {
            Write-Warning 'release has no checksums.txt; the download was not verified'
        } else {
            throw 'refusing to install without checksums.txt (set SSH_CLI_ALLOW_MISSING_CHECKSUM=1 to override)'
        }
    }
    if ($haveSums) {
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
