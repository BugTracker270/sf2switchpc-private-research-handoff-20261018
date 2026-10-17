param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [Parameter(Mandatory=$true)][ValidateSet('sdk','subsdk0')][string]$Module,[int]$BatchSize=2000)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if (Test-Path -LiteralPath "$Root\analysis\nso\SF2-aux-$Module-v1.gpr") { throw 'Preserve prior pass; inspect existing module state before resuming manually' }
for ($batch=1;$batch -le 30;$batch++) {
 $parameters=@{Root=$Root;Module=$Module;Limit=$BatchSize}
 if ($batch -gt 1) { $parameters.Resume=$true }
 & "$PSScriptRoot\Invoke-AuxiliaryModuleRecovery.ps1" @parameters *> "$Root\logs\auxiliary-$Module-pass-$batch.log"
 $state=Get-Content -LiteralPath "$Root\reports\native-auxiliary-$Module-v1.json" -Raw | ConvertFrom-Json
 Write-Output "$Module batch $batch : $($state.progress.completed_records)/$($state.progress.total_targets) ranges"
 if ($state.status -eq 'AUXILIARY_RANGE_EXPORT_COMPLETE') { break }
 if ($state.status -ne 'AUXILIARY_RANGE_EXPORT_IN_PROGRESS') { throw 'Auxiliary pass failed a gate; inspect exact logs' }
}
