<#
.SYNOPSIS
    Downloads verified EVTX samples from the pinned GitHub commit and verifies SHA-256 hashes.
.DESCRIPTION
    Fetches the 6 curated EVTX files from sbousseaden/EVTX-ATTACK-SAMPLES at commit 4ceed2f4706daf601c212a8f91c113dd85349a2c
    and saves them to data/raw/, verifying each SHA-256 against data/dataset_inventory.csv.
.PARAMETER Force
    Overwrites existing files even if they are present.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/fetch_samples.ps1
#>

[CmdletBinding()]
param(
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$RawDir = Join-Path $RootDir "data\raw"
$InventoryPath = Join-Path $RootDir "data\dataset_inventory.csv"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " EVTX Sample Acquisition & Hash Verification Script       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Project root: $RootDir" -ForegroundColor Gray
Write-Host "[*] Target directory: $RawDir" -ForegroundColor Gray

if (-not (Test-Path $RawDir)) {
    Write-Host "[*] Creating data\raw directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $RawDir | Out-Null
}

if (-not (Test-Path $InventoryPath)) {
    Write-Error "[-] Dataset inventory not found at: $InventoryPath"
    exit 1
}

$inventory = Import-Csv -Path $InventoryPath
$pinnedCommit = "4ceed2f4706daf601c212a8f91c113dd85349a2c"
$allVerified = $true

Write-Host "`n[*] Processing $($inventory.Count) datasets from inventory..." -ForegroundColor Yellow

foreach ($row in $inventory) {
    $filename = $row.filename
    $subfolder = $row.upstream_subfolder
    $expectedHash = $row.sha256.ToLower().Trim()
    $destFile = Join-Path $RawDir $filename

    $encodedSubfolder = [System.Uri]::EscapeDataString($subfolder)
    $encodedFilename = [System.Uri]::EscapeDataString($filename)
    $downloadUrl = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/$pinnedCommit/$encodedSubfolder/$encodedFilename"

    Write-Host "`n--- [$($row.dataset_id)] $filename ---" -ForegroundColor Cyan

    $needsDownload = $Force -or (-not (Test-Path $destFile))

    if (-not $needsDownload) {
        $actualHash = (Get-FileHash -Path $destFile -Algorithm SHA256).Hash.ToLower()
        if ($actualHash -eq $expectedHash) {
            Write-Host "[+] Present & verified: $filename (SHA-256 match)" -ForegroundColor Green
            continue
        } else {
            Write-Host "[!] Existing file hash mismatch. Re-downloading..." -ForegroundColor Yellow
            $needsDownload = $true
        }
    }

    if ($needsDownload) {
        Write-Host "[*] Downloading from: $downloadUrl" -ForegroundColor Gray
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $downloadUrl -OutFile $destFile -UseBasicParsing -TimeoutSec 30
            Write-Host "[+] Download complete: $filename" -ForegroundColor Green
        } catch {
            Write-Error "[-] Download failed for $filename : $_"
            $allVerified = $false
            continue
        }
    }

    $actualHash = (Get-FileHash -Path $destFile -Algorithm SHA256).Hash.ToLower()
    if ($actualHash -eq $expectedHash) {
        Write-Host "[+] Hash MATCH: $actualHash" -ForegroundColor Green
    } else {
        Write-Error "[-] Hash MISMATCH for $filename`n    Expected: $expectedHash`n    Actual:   $actualHash"
        $allVerified = $false
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
if ($allVerified) {
    Write-Host "[SUCCESS] All 6 EVTX samples verified and match inventory hashes." -ForegroundColor Green
} else {
    Write-Error "[FAIL] One or more samples failed acquisition or hash verification."
    exit 1
}
