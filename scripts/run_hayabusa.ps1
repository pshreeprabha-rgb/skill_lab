<#
.SYNOPSIS
    Automated execution script for Hayabusa v4.2.0 Windows Event Log Threat Hunting.
.DESCRIPTION
    Scans genuine EVTX files in data/raw/ using Hayabusa v4.2.0 dfir-timeline mode.
    Outputs the raw detection timeline to outputs/raw/hayabusa_raw_output.csv and
    logs execution metrics to outputs/raw/hayabusa_run_log.txt.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/run_hayabusa.ps1
#>

[CmdletBinding()]
param(
    [string]$RootDir = ""
)

$ErrorActionPreference = "Stop"

if (-not $RootDir) {
    $RootDir = Split-Path -Parent $PSScriptRoot
}

$RawDir = Join-Path $RootDir "data\raw"
$HayabusaExe = Join-Path $RootDir "hayabusa\hayabusa.exe"
$OutputDir = Join-Path $RootDir "outputs\raw"
$OutputCsv = Join-Path $OutputDir "hayabusa_raw_output.csv"
$LogFile = Join-Path $OutputDir "hayabusa_run_log.txt"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Windows Threat Hunting Pipeline: Hayabusa v4.2.0 Runner " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Project root: $RootDir" -ForegroundColor Gray

if (-not (Test-Path $OutputDir)) {
    Write-Host "[*] Creating output directory: $OutputDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
}

# Check Hayabusa executable
if (-not (Test-Path $HayabusaExe)) {
    Write-Error "[-] Hayabusa executable not found at: $HayabusaExe"
    exit 1
}
Write-Host "[+] Found Hayabusa executable: $HayabusaExe" -ForegroundColor Green

# Check raw EVTX input files
if (-not (Test-Path $RawDir)) {
    Write-Error "[-] Input directory not found: $RawDir"
    exit 1
}

$evtxFiles = Get-ChildItem -Path $RawDir -Filter *.evtx
if ($evtxFiles.Count -eq 0) {
    Write-Error "[-] No .evtx files found in: $RawDir"
    exit 1
}

Write-Host "[+] Found $($evtxFiles.Count) EVTX files in $RawDir" -ForegroundColor Green
foreach ($f in $evtxFiles) {
    Write-Host "    - $($f.Name) ($([math]::Round($f.Length / 1KB, 1)) KB)" -ForegroundColor Gray
}

# Execute Hayabusa dfir-timeline
Write-Host "`n[*] Starting Hayabusa dfir-timeline analysis..." -ForegroundColor Yellow
Write-Host "    Command: & `"$HayabusaExe`" dfir-timeline -d `"$RawDir`" -o `"$OutputCsv`" -U -w -C" -ForegroundColor Gray

$sw = [System.Diagnostics.Stopwatch]::StartNew()

try {
    & $HayabusaExe dfir-timeline -d "$RawDir" -o "$OutputCsv" -U -w -C | Out-File -FilePath "$LogFile" -Encoding utf8
    $sw.Stop()

    if ($LASTEXITCODE -ne 0) {
        Write-Error "[-] Hayabusa exited with error code: $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    Write-Host "[+] Hayabusa execution completed successfully in $($sw.Elapsed.TotalSeconds.ToString('F2'))s" -ForegroundColor Green
}
catch {
    Write-Error "[-] Execution failed: $_"
    exit 1
}

# Verify generated output
if (Test-Path $OutputCsv) {
    $item = Get-Item $OutputCsv
    $lineCount = (Get-Content -Path $OutputCsv | Measure-Object -Line).Lines
    Write-Host "[+] Generated CSV: $OutputCsv" -ForegroundColor Green
    Write-Host "    Size: $([math]::Round($item.Length / 1KB, 1)) KB, Rows: $lineCount" -ForegroundColor Green
} else {
    Write-Error "[-] Expected output file not found: $OutputCsv"
    exit 1
}

if (Test-Path $LogFile) {
    Write-Host "[+] Run log preserved: $LogFile" -ForegroundColor Green
}

Write-Host "`n[DONE] Hayabusa execution finished. Ready for data processing." -ForegroundColor Cyan
