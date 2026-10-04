param(
    [string]$Version = "dev",
    [string]$Go = "go"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$OutputDirectory = Join-Path $ProjectRoot "dist"
$PreviousGOOS = $env:GOOS
$PreviousGOARCH = $env:GOARCH
$PreviousCGO = $env:CGO_ENABLED

if ($Version -notmatch '^[0-9A-Za-z._+-]+$') {
    throw "Version may contain only letters, numbers, dots, underscores, plus or minus signs."
}

Push-Location $ProjectRoot
try {
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    & $Go build -trimpath -ldflags "-s -w -X main.version=$Version" -o (Join-Path $OutputDirectory "tailgate.exe") ./cmd/tailgate
    if ($LASTEXITCODE -ne 0) { throw "Go build failed with exit code $LASTEXITCODE." }
    Write-Host "Built dist/tailgate.exe ($Version), Windows amd64, CGO disabled."
}
finally {
    $env:GOOS = $PreviousGOOS
    $env:GOARCH = $PreviousGOARCH
    $env:CGO_ENABLED = $PreviousCGO
    Pop-Location
}
