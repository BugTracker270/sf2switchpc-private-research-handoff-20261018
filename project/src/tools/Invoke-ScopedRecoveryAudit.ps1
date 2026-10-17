param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [Parameter(Mandatory=$true)][string]$RunName)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid recovery run' }
$assemblies=Assert-UsbDestination $Root "$Root\analysis\il2cpp\cpp2il-recovery-$RunName"
$audit=Assert-UsbDestination $Root "$Root\analysis\il2cpp\cil-audit-$RunName"
$source=Assert-UsbDestination $Root "$Root\analysis\il2cpp\cpp2il-csharp-$RunName"
if ((Test-Path -LiteralPath $audit) -or (Test-Path -LiteralPath $source)) { throw 'Preserve existing audit output' }
dotnet "$Root\src\re\ManagedAudit\bin\Release\net10.0\ManagedAudit.dll" $Root $assemblies $audit *> "$Root\logs\cpp2il-$RunName-cil-audit.log"
$auditCode=$LASTEXITCODE
$results=@()
foreach ($target in @(@('VersionContainer','Assembly-CSharp-firstpass.dll','version'),@('Nekki.SF2.Core.Fights.Model.Components.Figures.Triangle','Assembly-CSharp.dll','triangle'))) {
 & "$Root\tools\ilspycmd\ilspycmd.exe" -t $target[0] -o (Assert-UsbDestination $Root "$source\$($target[2])") "$assemblies\$($target[1])" *> "$Root\logs\ilspy-$RunName-$($target[2]).log"
 $results+=@{type=$target[0];assembly=$target[1];exit_code=$LASTEXITCODE}
}
$malformed=$null
if ($auditCode -eq 0) {
 $summary=Get-Content -LiteralPath "$audit\summary.json" -Raw | ConvertFrom-Json
 $malformed=($summary.assemblies | Measure-Object -Property malformed_il -Sum).Sum
}
@{run=$RunName;cil_audit_exit_code=$auditCode;malformed_il=$malformed;scoped_exports=$results;scope='Opcode/operand syntax audit and two ILSpy exports; not semantic correctness or source compilation'} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\logs\cpp2il-$RunName-scoped-audit-result.json")
if ($auditCode -ne 0 -or $null -eq $malformed -or $malformed -ne 0 -or @($results | Where-Object exit_code -NE 0).Count -ne 0) { throw 'Recovery audit/export failed; exact logs preserved' }
python "$Root\src\re\tools\audit_scoped_csharp_types.py" --run $RunName *> "$Root\logs\scoped-csharp-type-audit-$RunName.log"
if ($LASTEXITCODE -ne 0) { throw 'Scoped C# type audit failed' }
dotnet "$Root\src\re\CilStackAudit\bin\Release\net10.0\CilStackAudit.dll" $Root $RunName *> "$Root\logs\cil-stack-audit-$RunName.log"
if ($LASTEXITCODE -ne 0) { throw 'Stack/header audit tool failed' }
$stack=Get-Content -LiteralPath "$Root\reports\cil-stack-audit-$RunName.json" -Raw | ConvertFrom-Json
if ($stack.status -ne 'PASS_STACK_DEPTH_AND_HEADERS_ONLY') { throw 'Recovered stack/header gate failed; preserve diagnostic report' }
Get-Content -LiteralPath "$Root\logs\scoped-csharp-type-audit-$RunName.log"
