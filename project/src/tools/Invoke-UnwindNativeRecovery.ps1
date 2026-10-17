param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [int]$StartBatch=2,[int]$MaximumBatches=40,[int]$BatchSize=2000,
 [string]$RunName='unwind-v1-main-001')
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($StartBatch -lt 1 -or $StartBatch+$MaximumBatches -gt 1000 -or $MaximumBatches -lt 1 -or $BatchSize -lt 1 -or $BatchSize -gt 5000 -or $RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid bounded recovery run' }
$logs=Assert-UsbDestination $Root "$Root\logs\$RunName"
if (Test-Path -LiteralPath $logs) { throw 'Preserve previous run logs' }
$null=New-Item -ItemType Directory -Path $logs
$state=@{status='IN_PROGRESS';current_batch=$StartBatch;completed_batches=@();full_semantic_reverse_engineering='NOT_COMPLETE';scope='Validated unwind-entry pseudocode/disassembly exports only; no Windows implementation or semantic completion claim'}
function Save-State { $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$logs\progress.json") }
Save-State
python "$Root\src\re\tools\summarize_unwind_recovery.py" *> "$logs\initial-coverage.log"
if ($LASTEXITCODE -ne 0) { throw 'Initial unwind integrity/coverage check failed' }
for ($offset=0;$offset -lt $MaximumBatches;$offset++) {
 $batch=$StartBatch+$offset;$name='unwind-v1-{0:D3}' -f $batch
 $state.current_batch=$batch;Save-State
 $null=Assert-UsbSpace $Root 8GB
 python "$Root\src\re\tools\select_unwind_native.py" --batch $batch --limit $BatchSize *> "$logs\$name-selection.log"
 $selectionCode=$LASTEXITCODE
 if ($selectionCode -eq 3) {
  $coverage=Get-Content -LiteralPath "$Root\reports\native-unwind-recovery.json" -Raw | ConvertFrom-Json
  $state.status=if ($coverage.failed_ranges -eq 0) { 'UNWIND_RANGE_EXPORT_COMPLETE' } else { 'EXPORTS_PENDING_REPAIR' }
  Save-State;break
 }
 if ($selectionCode -ne 0) { $state.status='SELECTION_FAILURE';Save-State;throw "Selection failed; inspect $logs" }
 $selection=Get-Content -LiteralPath "$Root\analysis\nso\$name-selection.json" -Raw | ConvertFrom-Json
 $timer=[Diagnostics.Stopwatch]::StartNew()
 try {
  & "$PSScriptRoot\Invoke-NativeCorpus.ps1" -Root $Root -Targets "analysis/nso/$name-targets.json" -OutputFolder "analysis/nso/native-engine-$name" -MaximumNewFunctions $selection.selected -TimeoutSeconds 120 -RequireComplete *> "$logs\$name-export.log"
 } catch {
  $state.status='EXPORT_FAILURE_NEEDS_REPAIR';$state.error=$_.Exception.Message;Save-State;throw
 }
 python "$Root\src\re\tools\native_corpus_index.py" --append-folder "native-engine-$name" *> "$logs\$name-index.log"
 if ($LASTEXITCODE -ne 0) { $state.status='INDEX_FAILURE';Save-State;throw "Incremental index failed; inspect $logs" }
 python "$Root\src\re\tools\summarize_unwind_recovery.py" *> "$logs\$name-coverage.log"
 if ($LASTEXITCODE -ne 0) { $state.status='COVERAGE_FAILURE';Save-State;throw "Coverage update failed; inspect $logs" }
 $timer.Stop()
 $state.completed_batches+=@{batch=$batch;selected=$selection.selected;elapsed_research_seconds=$timer.Elapsed.TotalSeconds;corpus="native-engine-$name"}
 Save-State
 Write-Output "Completed $name ($($selection.selected) native range exports); coverage and exact logs saved."
}
if ($state.status -eq 'IN_PROGRESS') { $state.status='BOUNDED_RUN_FINISHED';Save-State }
Get-Content -LiteralPath "$Root\reports\native-unwind-recovery.json"
