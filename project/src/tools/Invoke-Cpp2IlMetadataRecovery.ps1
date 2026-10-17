param([string]$Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [string]$RunName='nso-metadata',[switch]$RecoverAttributes,[switch]$OriginalMarkersOnly,[switch]$RecoverHfa)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
$null=Assert-UsbSpace $Root 8GB
if ($RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid run name' }
$env:MSBUILDDISABLENODEREUSE='1'
$env:CPP2IL_LEGACY_HFA=if($RecoverHfa){'1'}else{'0'}
dotnet build "$Root\refs\Cpp2IL\Cpp2IL\Cpp2IL.csproj" -c Release -f net10.0 --no-restore --property:NuGetAudit=false --maxcpucount:1 --nodeReuse:false *> "$Root\logs\cpp2il-$RunName-build.log"
if ($LASTEXITCODE -ne 0) { throw 'Cpp2IL metadata patch build failed' }
$env:DOTNET_GCHeapHardLimit='60000000'
$output=Assert-UsbDestination $Root "$Root\analysis\il2cpp\cpp2il-recovery-$RunName"
if (Test-Path -LiteralPath $output) { throw 'Preserve existing recovery output' }
$processorArguments=@()
if ($RecoverAttributes) { $processorArguments=@('--use-processor','attributeinjector') }
if ($OriginalMarkersOnly) {
 if (-not $RecoverAttributes) { throw 'Original marker view requires attribute processing' }
 $processorArguments+=@('--processor-config','attr-injector-original-markers-only=true')
}
$toolHashes=@{}
foreach ($toolAssembly in @('Cpp2IL.dll','Cpp2IL.Core.dll','LibCpp2IL.dll')) {
 $toolHashes[$toolAssembly]=(Get-FileHash -LiteralPath "$Root\refs\Cpp2IL\Cpp2IL\bin\Release\net10.0\$toolAssembly" -Algorithm SHA256).Hash.ToLowerInvariant()
}
$binaryHash=(Get-FileHash -LiteralPath "$Root\unpacked\effective\exefs\main" -Algorithm SHA256).Hash.ToLowerInvariant()
$metadataHash=(Get-FileHash -LiteralPath "$Root\unpacked\effective\romfs\Data\Managed\Metadata\global-metadata.dat" -Algorithm SHA256).Hash.ToLowerInvariant()
dotnet "$Root\refs\Cpp2IL\Cpp2IL\bin\Release\net10.0\Cpp2IL.dll" --force-binary-path "$Root\unpacked\effective\exefs\main" --force-metadata-path "$Root\unpacked\effective\romfs\Data\Managed\Metadata\global-metadata.dat" --force-unity-version 2018.1.9f1 --low-memory-mode --output-as dll_il_recovery --output-to $output @processorArguments *> "$Root\logs\cpp2il-$RunName-recovery.log"
$code=$LASTEXITCODE
@{exit_code=$code;utc=[DateTime]::UtcNow.ToString('o');output=$output;processors=$processorArguments;legacy_hfa_recovery=[bool]$RecoverHfa;tool_assembly_sha256=$toolHashes;source_binary_sha256=$binaryHash;source_metadata_sha256=$metadataHash;scope='Experimental tool recovery; compare diagnostics and native code before accepting semantics'} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\logs\cpp2il-$RunName-result.json")
if ($code -ne 0) { throw 'Metadata recovery failed; preserve exact logs' }
Get-Content -LiteralPath "$Root\logs\cpp2il-$RunName-recovery.log" -Tail 8
