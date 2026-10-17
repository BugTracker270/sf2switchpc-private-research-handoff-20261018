param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [Parameter(Mandatory=$true)][ValidateSet('rtld','sdk','subsdk0')][string]$Module,[int]$Limit=500,
 [string]$JavaHome='C:\Program Files\Java\jdk-26.0.2',[switch]$Resume)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
$project="SF2-aux-$Module-v1"
if ($Limit -lt 1 -or $Limit -gt 5000) { throw 'Invalid bounded auxiliary pass' }
$exists=Test-Path -LiteralPath "$Root\analysis\nso\$project.gpr"
if ($exists -and -not $Resume) { throw 'Preserve previous auxiliary project; explicit resume required' }
if ($Resume -and -not $exists) { throw 'Cannot resume a missing auxiliary project' }
if (-not $Resume) {
 python "$Root\src\re\tools\prepare_auxiliary_module.py" --module $Module --limit $Limit *> "$Root\logs\auxiliary-$Module-v1-prepare.log"
 if ($LASTEXITCODE -ne 0) { throw 'Auxiliary target preparation failed' }
}
$folder=Assert-UsbDestination $Root "$Root\analysis\nso\auxiliary-$Module-v1"
$inputNso=Assert-UsbDestination $Root "$Root\unpacked\effective\exefs\$Module"
$env:JAVA_HOME=$JavaHome;$env:GHIDRA_HEADLESS_MAXMEM='1600M'
$env:GHIDRA_HEADLESS_JAVA_OPTIONS="-Dapplication.settingsdir=$Root\cache\ghidra-settings -Dapplication.cachedir=$Root\cache\ghidra-cache -Dapplication.tempdir=$Root\cache\ghidra-temp -Dsf2.root=$Root"
$stamp=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$console="$Root\logs\auxiliary-$Module-$stamp-console.log";$log="$Root\logs\auxiliary-$Module-$stamp.log"
$inputArguments=if ($Resume) { @('-process',$Module) } else { @('-import',$inputNso) }
& "$Root\tools\ghidra\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat" "$Root\analysis\nso" $project @inputArguments -noanalysis -max-cpu 2 -scriptPath "$Root\src\re\tools" -postScript ExportNativeCorpus.java "$folder\targets.json" "$folder\corpus" $Limit 120 -log $log *> $console
$code=$LASTEXITCODE
$report=@{module=$Module;exit_code=$code;status='AUXILIARY_IMPORT_EXPORT_NEEDS_REVIEW';project=$project;console=$console;scope='Independent module range pseudocode/disassembly exports only. No main index mutation or complete clean source claim.'}
if ($code -eq 0 -and -not (Select-String -LiteralPath $console -Pattern 'Error running script|SCRIPT ERROR|error: cannot find symbol' -Quiet)) {
 $progress=Get-Content -LiteralPath "$folder\corpus\progress.json" -Raw | ConvertFrom-Json
 $report.progress=$progress
 if ($progress.failed_records -eq 0) {
  $report.status=if ($progress.completed_records -eq $progress.total_targets) { 'AUXILIARY_RANGE_EXPORT_COMPLETE' } else { 'AUXILIARY_RANGE_EXPORT_IN_PROGRESS' }
 }
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\native-auxiliary-$Module-v1.json") -Encoding utf8
if ($report.status -notin @('AUXILIARY_RANGE_EXPORT_COMPLETE','AUXILIARY_RANGE_EXPORT_IN_PROGRESS')) { throw 'Auxiliary import/export failed a gate; preserve exact logs/project' }
Write-Output "$Module : $($report.status)"
