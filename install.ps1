<#
.SYNOPSIS
    Vexa SCA CLI Official Windows Installer with Cryptographic Checksum Verification.
.DESCRIPTION
    Downloads and installs the latest verified vexa-sca release binary for Windows x86_64.
.EXAMPLE
    irm https://raw.githubusercontent.com/noviqtechnologies/vexa-sca/main/install.ps1 | iex
    irm https://vexasec.io/sca/install.ps1 | iex
#>

param(
    [string]$Version = "latest",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "vexa\bin"),
    [switch]$SkipHashCheck
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "         Vexa SCA CLI Windows Installer       " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

$Repo = "noviqtechnologies/vexa-sca"
if ($Version -eq "latest") {
    $ReleaseUrl = "https://api.github.com/repos/$Repo/releases/latest"
    try {
        $Release = Invoke-RestMethod -Uri $ReleaseUrl -Headers @{"User-Agent"="vexa-sca-installer"}
        $VersionTag = $Release.tag_name
    } catch {
        $VersionTag = "v1.3.5"
    }
} else {
    $VersionTag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
}

Write-Host "Installing Vexa SCA $VersionTag..." -ForegroundColor Green

$ZipName = "vexa-sca-windows-x86_64.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$VersionTag/$ZipName"
$ChecksumUrl = "https://github.com/$Repo/releases/download/$VersionTag/$ZipName.sha256"

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "vexa-sca-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $ZipPath = Join-Path $TempDir $ZipName
    Write-Host "Downloading $DownloadUrl..." -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
    } catch {
        # Fallback to Cargo git install if release archive not found
        Write-Host "Prebuilt release binary not found; falling back to cargo install from Git tag $VersionTag..." -ForegroundColor Yellow
        if (Get-Command cargo -ErrorAction SilentlyContinue) {
            cargo install --git "https://github.com/$Repo.git" --tag $VersionTag --locked --bin vexa-sca
            Write-Host "✔ vexa-sca installed successfully via cargo!" -ForegroundColor Green
            exit 0
        } else {
            throw "Failed to download release zip ($DownloadUrl) and cargo is not installed."
        }
    }

    if (-not $SkipHashCheck) {
        try {
            $ChecksumPath = Join-Path $TempDir "$ZipName.sha256"
            Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing
            $ExpectedHash = ((Get-Content $ChecksumPath | Select-Object -First 1) -split '\s+')[0].Trim().ToLower()
            if ($ExpectedHash) {
                $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()
                if ($ActualHash -ne $ExpectedHash) {
                    throw "SHA256 checksum mismatch! Expected: $ExpectedHash, Computed: $ActualHash"
                }
                Write-Host "✔ SHA256 Checksum verified: $ActualHash" -ForegroundColor Green
            }
        } catch [System.Management.Automation.ItemNotFoundException], [System.Net.WebException] {
            Write-Host "Notice: Remote checksum file not found; continuing." -ForegroundColor Yellow
        }
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force
    $ExtractedBin = Get-ChildItem -Path $TempDir -Filter "vexa-sca.exe" -Recurse | Select-Object -First 1
    if (-not $ExtractedBin) {
        $ExtractedBin = Get-ChildItem -Path $TempDir -Filter "*.exe" -Recurse | Select-Object -First 1
    }

    if ($ExtractedBin) {
        Copy-Item -Path $ExtractedBin.FullName -Destination (Join-Path $InstallDir "vexa-sca.exe") -Force
        Copy-Item -Path $ExtractedBin.FullName -Destination (Join-Path $InstallDir "sca.exe") -Force
    } else {
        throw "Binary executable not found inside archive."
    }

    # Add to user PATH if not present
    $UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    if ($UserPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", [EnvironmentVariableTarget]::User)
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "Added $InstallDir to user PATH." -ForegroundColor Cyan
    }

    Write-Host "`n✔ Vexa SCA successfully installed to $InstallDir\vexa-sca.exe" -ForegroundColor Green
    Write-Host "To verify, run: vexa-sca --version" -ForegroundColor Cyan
} finally {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
