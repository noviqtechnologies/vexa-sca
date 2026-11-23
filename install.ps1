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
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "vexa\bin")
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "         Vexa SCA CLI Windows Installer       " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

$Repo = "noviqtechnologies/vexa-sca"
if ($Version -eq "latest") {
    $ReleaseUrl = "https://api.github.com/repos/$Repo/releases/latest"
    $Release = Invoke-RestMethod -Uri $ReleaseUrl -Headers @{"User-Agent"="vexa-sca-installer"}
    $VersionTag = $Release.tag_name
} else {
    $VersionTag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
}

if ([string]::IsNullOrWhiteSpace($VersionTag) -or ($VersionTag -notmatch '^v\d+\.\d+\.\d+(-[A-Za-z0-9._-]+)?$')) {
    throw "Invalid or missing release tag '$VersionTag' (expected vX.Y.Z); failing closed."
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

    # Mandatory SHA-256 verification (fail-closed)
    $ChecksumPath = Join-Path $TempDir "$ZipName.sha256"
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing
    $ExpectedHash = ((Get-Content $ChecksumPath | Select-Object -First 1) -split '\s+')[0].Trim().ToLower()
    if ($ExpectedHash -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid or missing SHA-256 digest in $ZipName.sha256; failing closed."
    }
    $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()
    if ($ActualHash -ne $ExpectedHash) {
        throw "SHA256 checksum mismatch! Expected: $ExpectedHash, Computed: $ActualHash"
    }
    Write-Host "✔ SHA256 Checksum verified: $ActualHash" -ForegroundColor Green

    # Rollback protection
    $ExistingExe = Join-Path $InstallDir "vexa-sca.exe"
    if ((Test-Path -LiteralPath $ExistingExe) -and ($env:VEXA_ALLOW_DOWNGRADE -ne "1")) {
        $ExistingOut = & $ExistingExe --version 2>$null
        if ($ExistingOut -match '(\d+\.\d+\.\d+)') {
            $ExistingVer = [Version]$Matches[1]
            $ReqVerStr = ($VersionTag -replace '^v', '') -split '-' | Select-Object -First 1
            if ([Version]$ReqVerStr -lt $ExistingVer) {
                throw "Rollback rejected: installed v$ExistingVer is newer than $VersionTag (set VEXA_ALLOW_DOWNGRADE=1 to override)."
            }
        }
    }

    # Mandatory publisher signature & provenance verification (fail-closed)
    $BaseUrl = "https://github.com/$Repo/releases/download/$VersionTag"
    $CertIdentity = "https://github.com/$Repo/.github/workflows/release-slsa-cosign.yml@refs/tags/$VersionTag"
    $OidcIssuer = "https://token.actions.githubusercontent.com"
    $CosignCmd = Get-Command cosign -ErrorAction SilentlyContinue
    $GhCmd = Get-Command gh -ErrorAction SilentlyContinue

    if ($CosignCmd) {
        $BundlePath = Join-Path $TempDir "$ZipName.sigstore.json"
        Invoke-WebRequest -Uri "$BaseUrl/$ZipName.sigstore.json" -OutFile $BundlePath -UseBasicParsing
        if (-not (Test-Path -LiteralPath $BundlePath) -or ((Get-Item -LiteralPath $BundlePath).Length -eq 0)) {
            throw "Downloaded $ZipName.sigstore.json is empty or missing; failing closed."
        }
        & $CosignCmd.Source verify-blob `
            --bundle $BundlePath `
            --certificate-identity $CertIdentity `
            --certificate-oidc-issuer $OidcIssuer `
            $ZipPath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Cosign signature verification failed for $VersionTag; failing closed."
        }
    } elseif ($GhCmd) {
        & $GhCmd.Source attestation verify $ZipPath `
            --repo $Repo `
            --signer-workflow "$Repo/.github/workflows/release-slsa-cosign.yml" `
            --source-ref "refs/tags/$VersionTag" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "GitHub SLSA provenance attestation verification failed for $ZipName; failing closed."
        }
    } else {
        throw "Mandatory publisher signature verification requires 'cosign' or 'gh' (GitHub CLI); neither was found in PATH. Failing closed."
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

    # Prepend to user PATH if not present so the newly installed binary takes precedence
    $UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    if ($UserPath -notlike "*$InstallDir*") {
        $NewUserPath = if ([string]::IsNullOrWhiteSpace($UserPath)) { $InstallDir } else { "$InstallDir;$UserPath" }
        [Environment]::SetEnvironmentVariable("Path", $NewUserPath, [EnvironmentVariableTarget]::User)
        Write-Host "Added $InstallDir to user PATH." -ForegroundColor Cyan
    }
    if ($env:Path -notlike "*$InstallDir*") {
        $env:Path = "$InstallDir;$env:Path"
    }

    # Warn if an older vexa-sca binary earlier in PATH shadows the newly installed one
    $InstalledExe = Join-Path $InstallDir "vexa-sca.exe"
    $Shadowing = Get-Command vexa-sca -All -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -and ($_.Source -ne $InstalledExe) }
    $FirstResolved = Get-Command vexa-sca -ErrorAction SilentlyContinue
    if ($FirstResolved -and $FirstResolved.Source -and ($FirstResolved.Source -ne $InstalledExe)) {
        Write-Host "`n[WARN] Another 'vexa-sca' binary earlier in PATH is shadowing this installation:" -ForegroundColor Yellow
        Write-Host "       Shadowing: $($FirstResolved.Source)" -ForegroundColor Yellow
        Write-Host "       Installed: $InstalledExe" -ForegroundColor Yellow
        Write-Host "       Remove the older binary (e.g. Remove-Item '$($FirstResolved.Source)') or move $InstallDir earlier in PATH." -ForegroundColor Yellow
    } elseif ($Shadowing) {
        Write-Host "Note: Older vexa-sca binary also exists at $($Shadowing[0].Source) (currently shadowed by $InstalledExe)." -ForegroundColor Gray
    }

    Write-Host "`n✔ Vexa SCA successfully installed to $InstalledExe" -ForegroundColor Green
    Write-Host "To verify, run: vexa-sca --version" -ForegroundColor Cyan
} finally {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
