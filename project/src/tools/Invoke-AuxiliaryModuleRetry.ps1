param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [Parameter(Mandatory=$true)][ValidateSet('sdk','subsdk0','rtld')][string]$Module,
 [Parameter(Mandatory=$true)][string]$Attempt,[int]$TimeoutSeconds=300)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($Attempt -notmatch '^[a-z0-9-]+$' -or $TimeoutSeconds -lt 30 -or $TimeoutSeconds -gt 600) { throw 'Invalid bounded retry' }
$project="SF2-aux-$Module-v1"
if (-not (Test-Path -LiteralPath "$Root\analysis\nso\$project.gpr")) { throw 'Existing auxiliary project required' }
python "$Root\src\re\tools\auxiliary_recovery_overlay.py" --module $Module --prepare-overlay $Attempt *> "$Root\logs\auxiliary-$Module-retry-$Attempt-prepare.log"
if ($LASTEXITCODE -ne 0) { throw 'Retry preparation failed' }
$folder=Assert-UsbDestination $Root "$Root\analysis\nso\auxiliary-$Module-v1\overlay-$Attempt"
$env:JAVA_HOME='C:\Program Files\Java\jdk-26.0.2';$env:GHIDRA_HEADLESS_MAXMEM='1600M'
$env:GHIDRA_HEADLESS_JAVA_OPTIONS="-Dapplication.settingsdir=$Root\cache\ghidra-settings -Dapplication.cachedir=$Root\cache\ghidra-cache -Dapplication.tempdir=$Root\cache\ghidra-temp -Dsf2.root=$Root"
$console="$Root\logs\auxiliary-$Module-retry-$Attempt-console.log"
& "$Root\tools\ghidra\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat" "$Root\analysis\nso" $project -process $Module -noanalysis -max-cpu 2 -scriptPath "$Root\src\re\tools" -postScript ExportNativeCorpus.java "$folder\targets.json" $folder 5000 $TimeoutSeconds -log "$Root\logs\auxiliary-$Module-retry-$Attempt.log" *> $console
if ($LASTEXITCODE -ne 0 -or (Select-String -LiteralPath $console -Pattern 'Error running script|SCRIPT ERROR|error: cannot find symbol' -Quiet)) { throw 'Auxiliary retry failed; preserve original and overlay logs' }
python "$Root\src\re\tools\auxiliary_recovery_overlay.py" --module $Module *> "$Root\logs\auxiliary-$Module-retry-$Attempt-summary.log"
if ($LASTEXITCODE -ne 0) { throw 'Resolved inventory gate failed' }
$report=Get-Content -LiteralPath "$Root\reports\native-auxiliary-$Module-resolved-v1.json" -Raw | ConvertFrom-Json
if ($report.status -ne 'AUXILIARY_RANGE_EXPORT_COMPLETE') { throw 'Unresolved auxiliary ranges remain; inspect retry evidence' }
Write-Output "$Module : $($report.status) with preserved failed attempts"
