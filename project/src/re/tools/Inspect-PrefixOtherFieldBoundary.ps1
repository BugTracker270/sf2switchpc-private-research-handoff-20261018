param([Parameter(Mandatory=$true)][string]$Root, [Parameter(Mandatory=$true)][string]$Run)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Run -notmatch '^[a-z0-9-]+$') { throw 'Invalid recovery run' }
$taskReaderDll = Join-Path $Root "analysis/il2cpp/cpp2il-recovery-$Run/Assembly-CSharp-firstpass.dll"
$taskReaderAssembly = [System.Reflection.Assembly]::LoadFrom($taskReaderDll)
$taskReaderType = $taskReaderAssembly.GetType('BestHTTP.WebSocket.Frames.WebSocketFrameReader', $true)
if ($null -ne $taskReaderType.TypeInitializer) { throw 'Unreviewed type initializer' }
$taskReaderOther = @($taskReaderType.GetFields([System.Reflection.BindingFlags]'Instance,Public,NonPublic') | Where-Object { $_.Name -notin @('<IsFinal>k__BackingField','<Type>k__BackingField','<HasMask>k__BackingField','<Length>k__BackingField') })
if ($taskReaderOther.Count -ne 2 -or @($taskReaderOther | Where-Object { $_.FieldType -ne [byte[]] }).Count -ne 0) { throw 'Unreviewed other-field type' }
$taskReaderBoundaryOwner = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($taskReaderType)
if (@($taskReaderOther | Where-Object { -not [object]::ReferenceEquals($_.GetValue($taskReaderBoundaryOwner), $null) }).Count -ne 0) { throw 'Non-null other-field boundary' }
$taskReaderBoundaryReport = [ordered]@{
    status='PASS_OTHER_FIELDS_ARE_TWO_NULL_BYTE_ARRAY_REFERENCES'
    recovery_run=$Run
    assembly_sha256=(Get-FileHash -LiteralPath $taskReaderDll -Algorithm SHA256).Hash.ToLowerInvariant()
    other_field_count=2
    other_field_types=@($taskReaderOther | ForEach-Object { $_.FieldType.FullName })
    other_field_tokens=@($taskReaderOther | ForEach-Object { '0x{0:X8}' -f $_.MetadataToken })
    other_fields_initially_null=$true
    game_equals_invoked=$false
    game_instance_constructor_invoked=$false
    whole_read_invoked=$false
}
$taskReaderBoundaryPath = Join-Path $Root 'reports/virtual-stream-prefix-field-boundary-v37.json'
Assert-UsbDestination -Root $Root -Path $taskReaderBoundaryPath | Out-Null
$taskReaderBoundaryReport | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $taskReaderBoundaryPath -Encoding utf8
Write-Output $taskReaderBoundaryReport.status
