<#
.SYNOPSIS
  Runs all na_pentest enum shell scripts on a Linux target via pscp + plink,
  capturing each script's output to this Windows machine.

.DESCRIPTION
  1) Uploads each .sh in -ScriptDir to /tmp on the target with pscp.
  2) Runs it with plink (AD password auth) and captures stdout + stderr.
  3) Writes each result into a timestamped run folder under -OutDir.

.PARAMETER Target
  Linux hostname or IP.
.PARAMETER User
  Login name. AD: 'DOMAIN\user' (NETBIOS) or 'user@corp.local' (UPN).
.PARAMETER Password
  Password used for -pw auth (lab use; prefer keys in a real engagement).
.PARAMETER Port
  SSH port (default 22).
.PARAMETER ScriptDir
  Folder containing the .sh scripts.
.PARAMETER OutDir
  Root output folder (a timestamped subfolder is created per run).
.PARAMETER Plink / Pscp
  Path to plink/pscp (default: whatever is on PATH).
.PARAMETER CacheHostKey
  Do a one-time logon to accept the host key (required before -batch runs).
.PARAMETER Sudo
  Prefix the remote command with 'sudo' (for the root-only checks).
.PARAMETER SudoPassword
  Password for non-interactive sudo (echo | sudo -S). Keep it simple (no
  $, ", or backticks). Prefer -Sudo without this if the account has
  passwordless sudo.

.EXAMPLE
  .\run_all_enum.ps1 -Target 10.0.0.5 -User 'CORP\jsmith' -Password 'Pass123!' -CacheHostKey

.EXAMPLE
  .\run_all_enum.ps1 -Target 10.0.0.5 -User 'jsmith@corp.local' -Password 'Pass123!' -Sudo -SudoPassword 'Pass123!'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$User,
    [Parameter(Mandatory=$true)][string]$Password,
    [int]    $Port        = 22,
    [string] $ScriptDir   = "C:\Users\MURTHY\Downloads\na_pentest_scripts",
    [string] $OutDir      = "C:\Users\MURTHY\Downloads\na_pentest_scripts\output",
    [string] $Plink       = "plink",
    [string] $Pscp        = "pscp",
    [switch] $CacheHostKey,
    [switch] $Sudo,
    [string] $SudoPassword = ""
)

$ErrorActionPreference = "Continue"

# --- One-time: accept the host key so -batch doesn't abort later ---------
if ($CacheHostKey) {
    Write-Host "[*] Accepting host key for ${Target} (answer 'y' if prompted)..." -ForegroundColor Cyan
    "y" | & $Plink -P $Port -l $User -pw $Password $Target "echo hostkey-cached"
    Write-Host "    (if this printed 'Access denied', the key is cached but the creds may be wrong)"
}

# --- Sanity-check the tools are reachable ---------------------------------
foreach ($exe in @($Plink, $Pscp)) {
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
        Write-Warning "Not found on PATH: $exe  -> pass -Plink / -Pscp with a full path (e.g. 'C:\Program Files\PuTTY\plink.exe')"
    }
}

# --- Timestamped run folder (don't overwrite previous evidence) ----------
$runDir = Join-Path $OutDir (Get-Date -Format "yyyyMMdd_HHmmss")
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
Write-Host "[*] Output folder: $runDir" -ForegroundColor Cyan

$scripts = Get-ChildItem -Path $ScriptDir -Filter *.sh | Sort-Object Name
if (-not $scripts) { Write-Error "No .sh scripts found in $ScriptDir"; exit 1 }

$results = @()

foreach ($f in $scripts) {
    $s       = $f.Name
    $base    = [System.IO.Path]::GetFileNameWithoutExtension($s)
    $outFile = Join-Path $runDir "out_${base}.txt"

    Write-Host ""
    Write-Host "=== ${s} -> ${outFile} ===" -ForegroundColor Green

    # 1) Upload the script to /tmp
    Write-Host "  [*] Upload to /tmp ... " -NoNewline
    & $Pscp -batch -P $Port -l $User -pw $Password $f.FullName "${Target}:/tmp/${s}" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "upload FAILED"
        $results += [PSCustomObject]@{ Script = $s; Upload = "FAIL"; Run = "SKIP" }
        continue
    }
    Write-Host "ok" -ForegroundColor Green

    # 2) Build the remote command
    $remote = "chmod +x /tmp/${s} && bash /tmp/${s}"
    if ($Sudo) {
        if ($SudoPassword) { $remote = "echo `"$SudoPassword`" | sudo -S bash /tmp/${s}" }
        else               { $remote = "sudo bash /tmp/${s}" }
    }

    # 3) Run + capture stdout/stderr to the local file
    Write-Host "  [*] Run + capture ... " -NoNewline
    $output = @(& $Plink -batch -P $Port -l $User -pw $Password $Target $remote 2>&1)
    $code   = $LASTEXITCODE

    $header = "TARGET=$Target`nSCRIPT=$s`nTIME=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`nCMD=$remote`n" + ("-" * 60)
    $lines  = @($header) + $output
    $lines  | Out-File -FilePath $outFile -Encoding utf8

    if ($code -eq 0) { Write-Host "done (exit 0)" -ForegroundColor Green }
    else             { Write-Host "done (exit $code)" -ForegroundColor Yellow }
    $results += [PSCustomObject]@{ Script = $s; Upload = "OK"; Run = "exit $code" }
}

# --- Summary --------------------------------------------------------------
Write-Host ""
Write-Host "===== SUMMARY =====" -ForegroundColor Cyan
$results | Format-Table -AutoSize
Write-Host "Outputs written to: $runDir" -ForegroundColor Cyan
