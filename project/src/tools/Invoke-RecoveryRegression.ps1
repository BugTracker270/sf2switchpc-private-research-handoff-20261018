param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [Parameter(Mandatory=$true)][string]$RunName,[switch]$IncludeEnumerator,[switch]$IncludeBooleanReader)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid recovery run' }
$probeResults = [Collections.Generic.List[object]]::new()
function Invoke-RecoveredProbe([string]$Name,[string[]]$ProbeArguments,[string]$Suffix) {
 $binary=Assert-UsbDestination $Root "$Root\src\re\$Name\bin\Release\net10.0\$Name.dll"
 if (-not (Test-Path -LiteralPath $binary)) { throw "Build the original $Name probe first" }
 $log=Assert-UsbDestination $Root "$Root\logs\regression-$RunName-$Suffix.log"
 & dotnet $binary @ProbeArguments *> $log
 $code=$LASTEXITCODE
 $probeResults.Add(@{probe=$Name;suffix=$Suffix;exit_code=$code;log="logs/regression-$RunName-$Suffix.log";
  probe_sha256=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()})
 if ($code -eq 0) { Write-Output "PASS: $Name $Suffix" }
 else { Write-Output "FAIL: $Name $Suffix exit=$code; preserved $log" }
}
$source=Assert-UsbDestination $Root "$Root\analysis\il2cpp\cpp2il-recovery-$RunName"
$audit=Assert-UsbDestination $Root "$Root\analysis\il2cpp\cil-audit-$RunName"
if (Test-Path -LiteralPath $audit) { throw 'Preserve the existing CIL syntax audit' }
Invoke-RecoveredProbe 'ManagedAudit' @($Root,$source,$audit) 'syntax'
Invoke-RecoveredProbe 'CilStackAudit' @($Root,$RunName) 'stack'
Invoke-RecoveredProbe 'RecoveredScalarProbe' @($Root,$RunName) 'scalar-direct'
Invoke-RecoveredProbe 'RecoveredScalarProbe' @($Root,$RunName,'--isolate-accessors') 'scalar-isolated'
Invoke-RecoveredProbe 'RecoveredVectorProbe' @($Root,$RunName) 'vector'
Invoke-RecoveredProbe 'RecoveredBooleanProbe' @($Root,$RunName) 'boolean'
Invoke-RecoveredProbe 'RecoveredTweenProbe' @($Root,$RunName,'--with-wrapper-identities') 'nested-tween'
Invoke-RecoveredProbe 'RecoveredTypeTokenProbe' @($Root,$RunName) 'type-token'
Invoke-RecoveredProbe 'RecoveredConstructorProbe' @($Root,$RunName) 'constructor'
Invoke-RecoveredProbe 'RecoveredCurrencyScalarProbe' @($Root,$RunName) 'currency-scalars'
Invoke-RecoveredProbe 'RecoveredAggregateLeafProbe' @($Root,$RunName) 'aggregate-leaves'
Invoke-RecoveredProbe 'RecoveredLeafAccessorProbe' @($Root,$RunName) 'leaf-accessor'
Invoke-RecoveredProbe 'RecoveredStaticGetterProbe' @($Root,$RunName) 'static-getter'
Invoke-RecoveredProbe 'RecoveredExceptionProbe' @($Root,$RunName) 'exception-factory'
Invoke-RecoveredProbe 'RecoveredBoxProbe' @($Root,$RunName) 'primitive-box'
Invoke-RecoveredProbe 'RecoveredValueThisProbe' @($Root,$RunName) 'value-this-codec'
if ($IncludeEnumerator) {
 Invoke-RecoveredProbe 'RecoveredEnumeratorProbe' @($Root,$RunName) 'indirect-enumerator'
}
if ($IncludeBooleanReader) {
 Invoke-RecoveredProbe 'RecoveredBooleanReaderProbe' @($Root,$RunName) 'boolean-reader'
}
$failed=@($probeResults | Where-Object { $_.exit_code -ne 0 })
@{status=$(if($failed.Count){'FAIL_SCOPED_RECOVERY_REGRESSIONS'}else{'PASS_SCOPED_RECOVERY_REGRESSIONS'});
 recovery_run=$RunName;probes=$probeResults.ToArray();include_enumerator=[bool]$IncludeEnumerator;include_boolean_reader=[bool]$IncludeBooleanReader;
 whole_game_source_ready=$false;scope='Independent bounded production-CIL probes; individual reports retain exact input, token and native-code boundaries.'} |
 ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\recovery-regression-$RunName.json")
if ($failed.Count) { throw "$($failed.Count) recovery probes failed; preserve all individual reports and logs" }
Write-Output 'PASS: bounded recovery regressions; full source and game behavior remain separate gates'
