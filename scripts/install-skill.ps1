param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('claude', 'codex', 'cursor', 'copilot', 'opencode')]
    [string]$Agent,
    [string]$Project,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
$locations = @{
    claude = @('.claude/skills', '.claude/skills')
    codex = @('.agents/skills', '.agents/skills')
    cursor = @('.cursor/skills', '.cursor/skills')
    copilot = @('.copilot/skills', '.github/skills')
    opencode = @('.config/opencode/skills', '.opencode/skills')
}
if ($PSBoundParameters.ContainsKey('Project')) {
    if (-not (Test-Path -LiteralPath $Project -PathType Container)) {
        throw 'Project directory does not exist.'
    }
    $baseDirectory = (Resolve-Path -LiteralPath $Project).ProviderPath
    $relativeDirectory = $locations[$Agent][1]
} else {
    $baseDirectory = [Environment]::GetFolderPath('UserProfile')
    if (-not $baseDirectory) { throw 'User profile is unavailable; use -Project DIRECTORY.' }
    $relativeDirectory = $locations[$Agent][0]
}
$destination = Join-Path (Join-Path $baseDirectory $relativeDirectory) 'ssh-cli'
$target = Join-Path $destination 'SKILL.md'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'SKILL.md'
$identical = $false
$existingTarget = Get-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
if ($existingTarget) {
    if ($existingTarget.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Refusing to replace a symbolic link.'
    }
    if (-not $Force) {
        if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash) {
            $identical = $true
        } else {
            throw "Already exists: $target. Review it, then use -Force to update."
        }
    }
}
# A copied skill is not a successful installation without a working CLI.
$cliDirectory = if ($env:SSH_CLI_BIN) { $env:SSH_CLI_BIN } else { Join-Path $env:LOCALAPPDATA 'ssh-cli/bin' }
$cli = Join-Path $cliDirectory 'ssh-cli.exe'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
    $command = Get-Command ssh-cli -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        $cli = $command.Source
    } else {
        # Require checksums even if the caller enabled the legacy bypass.
        $previousChecksumSetting = $env:SSH_CLI_ALLOW_MISSING_CHECKSUM
        try {
            $env:SSH_CLI_ALLOW_MISSING_CHECKSUM = '0'
            & (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1')
        } finally {
            $env:SSH_CLI_ALLOW_MISSING_CHECKSUM = $previousChecksumSetting
        }
    }
}
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CLI installation failed; Skill was not installed.' }
$LASTEXITCODE = 0
$cliVersion = & $cli version
if ($LASTEXITCODE -ne 0 -or -not ($cliVersion -join '').Trim()) {
    throw 'ssh-cli version failed; repair the CLI before installing the Skill.'
}
Write-Output "CLI ready: $cli ($($cliVersion -join ' '))"
if ($identical) {
    Write-Output "ssh-cli skill already installed for ${Agent}:"
    Write-Output $target
    return
}
[IO.Directory]::CreateDirectory($destination) | Out-Null
[IO.File]::Copy($source, $target, [bool]$Force)
Write-Output "Installed ssh-cli skill for ${Agent}:"
Write-Output $target
Write-Output 'CLI verified. Configure hosts separately before remote operations.'
