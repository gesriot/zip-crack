<#
.SYNOPSIS
Builds the Go CLI and Fyne GUI for Windows.

.DESCRIPTION
Two things are easy to forget and both are required for a correct build:

- The GUI must link with -H=windowsgui, otherwise a console window opens
  behind the app window (the CLI must NOT use this flag, or it loses its
  stdout/stderr).
- The PE icon resources (rsrc_windows_amd64.syso / rsrc_windows_arm64.syso,
  in the repo root and cmd/gui) must already exist for Explorer/taskbar/
  pinned shortcuts to show the app icon. They are committed to the repo and
  only need regenerating if macos/icon-runtime.png changes:

    go install github.com/tc-hib/go-winres@latest
    go-winres simply --icon macos/icon-runtime.png --manifest cli --arch amd64,arm64
    go-winres simply --icon cmd/gui/icon.png --manifest gui --arch amd64,arm64  # run inside cmd/gui

.PARAMETER DistDir
Output directory (default: dist).
#>

[CmdletBinding()]
param(
    [string]$DistDir
)

$ErrorActionPreference = "Stop"

$rootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$rootPath = $rootDir.Path

if (-not $DistDir) {
    $DistDir = Join-Path $rootPath "dist"
}
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

Push-Location $rootPath
try {
    Write-Host "Building CLI (dist/zip_crack.exe)..."
    go build -o (Join-Path $DistDir "zip_crack.exe") .
    if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }

    Write-Host "Building GUI (dist/PasswordCracker-gui.exe)..."
    go build -ldflags "-H=windowsgui" -o (Join-Path $DistDir "PasswordCracker-gui.exe") ./cmd/gui
    if ($LASTEXITCODE -ne 0) { throw "GUI build failed" }
}
finally {
    Pop-Location
}

Write-Host "CLI: $(Join-Path $DistDir 'zip_crack.exe')"
Write-Host "GUI: $(Join-Path $DistDir 'PasswordCracker-gui.exe')"
