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
$existingTarget = Get-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
if ($existingTarget) {
    if ($existingTarget.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Refusing to replace a symbolic link.'
    }
    if (-not $Force) {
        if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash) {
            Write-Output "ssh-cli skill already installed for ${Agent}:"
            Write-Output $target
            return
        }
        throw "Already exists: $target. Review it, then use -Force to update."
    }
}
[IO.Directory]::CreateDirectory($destination) | Out-Null
[IO.File]::Copy($source, $target, [bool]$Force)
Write-Output "Installed ssh-cli skill for ${Agent}:"
Write-Output $target
Write-Output 'The ssh-cli executable and SSH inventory must be available in the agent environment.'
