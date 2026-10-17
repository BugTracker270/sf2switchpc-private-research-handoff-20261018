param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [string]$RunName=([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')))
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid run name' }
$logRoot=Assert-UsbDestination $Root "$Root\logs\native-regression-$RunName"
if (Test-Path -LiteralPath $logRoot) { throw 'Preserve previous regression run' }
$null=New-Item -ItemType Directory -Path $logRoot
$cases=@(
 @('ai_leaves','native-ai-execution.json'),
 @('node_step','native-node-integration.json'),
 @('save_gate','native-save-gate-execution.json'),
 @('contact_geometry','native-contact-geometry.json'),
 @('capsules','native-capsule-geometry.json'),
 @('strike_selection','native-strike-selection.json'),
 @('damage_combination','native-damage-combination.json'),
 @('empty_animation_gate','native-empty-animation-gate.json'),
 @('bezier','native-animation-bezier.json'),
 @('animation_step','native-animation-step.json'),
 @('quest_lookup','native-quest-lookup.json'),
 @('currency_codec','native-currency-codec.json'),
 @('currency_long','native-currency-long.json'),
 @('wallet','native-wallet-arithmetic.json'),
 @('save_scheduler','native-save-scheduler.json'),
 @('exception_boundary','native-exception-boundary.json'),
 @('array_boundary','native-array-boundary.json'),
 @('scalar_accessors','native-scalar-accessors.json')
)
$results=@()
foreach ($case in $cases) {
 $script=Assert-UsbDestination $Root "$Root\src\re\tools\execute_native_$($case[0]).py"
 $report=Assert-UsbDestination $Root "$Root\reports\$($case[1])"
 $timer=[Diagnostics.Stopwatch]::StartNew()
 & python $script *> "$logRoot\$($case[0]).log"
 $code=$LASTEXITCODE
 $timer.Stop()
 $result=$null
 if ($code -eq 0 -and (Test-Path -LiteralPath $report)) { $result=Get-Content -LiteralPath $report -Raw | ConvertFrom-Json }
 $passed=$code -eq 0 -and $null -ne $result -and $result.status -like 'PASS*'
 $checks=0
 if ($null -ne $result) {
  foreach ($field in @('checks','bit_exact_float_checks','passed')) {
   $property=$result.PSObject.Properties[$field]
   if ($null -ne $property -and $property.Value -is [System.ValueType]) { $checks=$property.Value; break }
  }
 }
 $results+=@{name=$case[0];exit_code=$code;passed=$passed;checks=$checks;elapsed_seconds=$timer.Elapsed.TotalSeconds;report=$case[1];script_sha256=(Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant()}
 if (-not $passed) { break }
}
$passedCount=@($results | Where-Object passed).Count
$summary=@{utc=[DateTime]::UtcNow.ToString('o');status=if ($passedCount -eq $cases.Count) { 'PASS_BOUNDED_NATIVE_REGRESSION' } else { 'FAILED_OR_INCOMPLETE' };passed_scopes=$passedCount;expected_scopes=$cases.Count;checks=($results | Measure-Object -Property checks -Sum).Sum;results=$results;log_directory=$logRoot;scope='Original ARM64 function/slice checks with documented synthetic objects, initialization, allocator models and explicit supplied runtime/persistence boundaries where stated. Elapsed values are research harness durations, never gameplay FPS or whole-runtime parity.'}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$logRoot\summary.json" -Encoding utf8
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\native-regression.json") -Encoding utf8
if ($passedCount -ne $cases.Count) { throw 'Native regression failed; exact per-scope log preserved' }
$summary | ConvertTo-Json -Depth 8
