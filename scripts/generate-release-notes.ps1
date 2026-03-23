param(
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

function Resolve-ReleaseTag([string]$Version) {
    if ($env:GITHUB_REF_NAME -and $env:GITHUB_REF_NAME.StartsWith("v")) {
        return $env:GITHUB_REF_NAME
    }
    return "v$Version"
}

function Resolve-PreviousTag([string]$ReleaseTag) {
    $tags = git tag --sort=-creatordate
    if (-not $tags) {
        return ""
    }
    foreach ($tag in $tags) {
        if ($tag -ne $ReleaseTag) {
            return $tag
        }
    }
    return ""
}

$version = Resolve-Version
$releaseTag = Resolve-ReleaseTag $version
$previousTag = Resolve-PreviousTag $releaseTag
$range = if ($previousTag -ne "") { "$previousTag..HEAD" } else { "HEAD" }

$commitLines = @(git log --pretty=format:'%s|%h' $range)
if (-not $commitLines -or $commitLines.Count -eq 0) {
    $commitLines = @("chore: release metadata refresh|HEAD")
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$notesFile = Join-Path $OutDir "RELEASE_NOTES.md"
$changelogFile = Join-Path $OutDir "CHANGELOG.md"
$today = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")

$sections = [ordered]@{
    feat = @{ title = "Features"; items = New-Object System.Collections.Generic.List[string] }
    fix = @{ title = "Fixes"; items = New-Object System.Collections.Generic.List[string] }
    security = @{ title = "Security"; items = New-Object System.Collections.Generic.List[string] }
    perf = @{ title = "Performance"; items = New-Object System.Collections.Generic.List[string] }
    refactor = @{ title = "Refactor"; items = New-Object System.Collections.Generic.List[string] }
    docs = @{ title = "Docs"; items = New-Object System.Collections.Generic.List[string] }
    test = @{ title = "Tests"; items = New-Object System.Collections.Generic.List[string] }
    build = @{ title = "Build"; items = New-Object System.Collections.Generic.List[string] }
    chore = @{ title = "Chore"; items = New-Object System.Collections.Generic.List[string] }
    other = @{ title = "Other"; items = New-Object System.Collections.Generic.List[string] }
}

$regex = '^(feat|fix|security|perf|refactor|docs|test|build|chore)(\([^)]+\))?!?:\s*(.+)$'
foreach ($line in $commitLines) {
    $parts = $line.Split("|", 2)
    $subject = $parts[0]
    $sha = if ($parts.Count -gt 1) { $parts[1] } else { "HEAD" }
    $type = "other"
    $text = $subject
    if ($subject -match $regex) {
        $type = $Matches[1]
        $text = $Matches[3]
    }
    $sections[$type].items.Add("- $text ($sha)")
}

$notes = New-Object System.Collections.Generic.List[string]
$notes.Add("# Release Notes $releaseTag")
$notes.Add("")
$notes.Add("- Date: $today (UTC)")
$notes.Add("- Version: $version")
if ($previousTag -ne "") {
    $notes.Add("- Diff: $previousTag..$releaseTag")
} else {
    $notes.Add("- Diff: initial release snapshot")
}
$notes.Add("")
$notes.Add("## Highlights")
$notes.Add("")

foreach ($entry in $sections.GetEnumerator()) {
    if ($entry.Value.items.Count -eq 0) { continue }
    $notes.Add("### $($entry.Value.title)")
    $notes.Add("")
    $notes.AddRange($entry.Value.items)
    $notes.Add("")
}

$changelog = New-Object System.Collections.Generic.List[string]
$changelog.Add("# Changelog")
$changelog.Add("")
$changelog.Add("## $releaseTag - $today")
$changelog.Add("")
if ($previousTag -ne "") {
    $changelog.Add("_Diff_: $previousTag..$releaseTag")
} else {
    $changelog.Add("_Diff_: initial release snapshot")
}
$changelog.Add("")
$highlightStart = $notes.IndexOf("## Highlights")
if ($highlightStart -ge 0) {
    for ($i = $highlightStart + 1; $i -lt $notes.Count; $i++) {
        $changelog.Add($notes[$i])
    }
}

Set-Content -Path $notesFile -Value ($notes -join "`n")
Set-Content -Path $changelogFile -Value ($changelog -join "`n")

Write-Host "Generated release metadata:"
Write-Host "  $notesFile"
Write-Host "  $changelogFile"
