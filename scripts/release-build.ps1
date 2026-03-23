param(
    [string]$Target = "",
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

function Resolve-Version {
    $cargoToml = Get-Content "Cargo.toml" -Raw
    $match = [regex]::Match($cargoToml, '(?m)^version\s*=\s*"([^"]+)"')
    if (-not $match.Success) {
        throw "Unable to resolve version from Cargo.toml"
    }
    return $match.Groups[1].Value
}

function Get-BinaryName {
    if ($IsWindows) {
        return "mia-secret.exe"
    }
    return "mia-secret"
}

function Compute-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
}

$version = Resolve-Version
$binaryName = Get-BinaryName
$targetArg = @()
$targetSuffix = ""
if ($Target -ne "") {
    $targetArg = @("--target", $Target)
    $targetSuffix = "-$Target"
}

Write-Host "Building release binary (version=$version target=$Target)"
cargo build --release @targetArg

$releaseDir = if ($Target -ne "") {
    Join-Path "target" (Join-Path $Target "release")
} else {
    Join-Path "target" "release"
}
$binaryPath = Join-Path $releaseDir $binaryName
if (-not (Test-Path $binaryPath)) {
    throw "Binary not found: $binaryPath"
}

$artifactBase = "mia-secret-v$version$targetSuffix-windows-x64"
$artifactDir = Join-Path $OutDir $artifactBase
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null

Copy-Item $binaryPath (Join-Path $artifactDir $binaryName) -Force
Copy-Item "README.md" (Join-Path $artifactDir "README.md") -Force
Copy-Item "docs/release.md" (Join-Path $artifactDir "RELEASE.md") -Force
Copy-Item "docs/api.md" (Join-Path $artifactDir "API.md") -Force
Copy-Item "docs/cli.md" (Join-Path $artifactDir "CLI.md") -Force

$zipPath = Join-Path $OutDir "$artifactBase.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}
Compress-Archive -Path (Join-Path $artifactDir "*") -DestinationPath $zipPath

$sha = Compute-Sha256 $zipPath
$shaLine = "$sha  $(Split-Path $zipPath -Leaf)"
$shaFile = "$zipPath.sha256"
Set-Content -Path $shaFile -Value $shaLine -NoNewline

Write-Host "Release artifact created:"
Write-Host "  $zipPath"
Write-Host "  $shaFile"
