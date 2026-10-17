param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [string]$RunName='rust-source-v1',[switch]$UseUncompressed,[switch]$UseNsoMappingFix)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid run name' }
$null=Assert-UsbSpace $Root 8GB
$repo="$Root\refs\il2cpp-dumper-rs"
$sourceLock=Get-Content -LiteralPath "$Root\reports\il2cpp-dumper-rs-source-lock.json" -Raw | ConvertFrom-Json
if ($sourceLock.commit -ne '145a751023258a35f133c4f111785a8df0580985') { throw 'Unexpected source pin' }
$overrides=@{}
if ($UseNsoMappingFix) {
 if (-not $UseUncompressed) { throw 'The isolated mapping experiment requires verified uncompressed input' }
 $patchLock=Get-Content -LiteralPath "$Root\reports\rust-nso-mapping-patch-lock.json" -Raw | ConvertFrom-Json
 if ($patchLock.commit -ne $sourceLock.commit -or @($patchLock.files).Count -ne 1 -or $patchLock.files[0].path -ne 'src/main.rs') { throw 'Unexpected mapping correction manifest' }
 $overrides['src/main.rs']=$patchLock.files[0].sha256
}
foreach ($file in $sourceLock.files) {
 if ([IO.Path]::IsPathRooted($file.path) -or $file.path -match '(^|[\\/])\.\.([\\/]|$)') { throw 'Invalid source manifest path' }
 $path=[IO.Path]::GetFullPath((Join-Path $repo $file.path))
 if (-not $path.StartsWith($repo+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Source path outside verified checkout' }
 Assert-NoReparse $path
 $expectedHash=if($overrides.ContainsKey($file.path)){$overrides[$file.path]}else{$file.sha256}
 if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw "Changed tool source: $($file.path)" }
}
$tool=Assert-UsbDestination $Root "$repo\target\release\il2cpp_dumper.exe"
$output=Assert-UsbDestination $Root "$Root\analysis\il2cpp\$RunName"
if (Test-Path -LiteralPath $output) { throw 'Preserve earlier probe output' }
New-Item -ItemType Directory -Path $output | Out-Null
$config=Get-Content -LiteralPath "$repo\config.json" -Raw | ConvertFrom-Json
$config.requireAnyKey=$false
$config.generateCppScaffold=$false
$config.generateUnityHeaders=$false
$config.generateStruct=$false
$config.generateGenericsDump=$false
$config.methodBodyMode='csharp'
$configPath=Assert-UsbDestination $Root "$output\probe-config.json"
$config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath -Encoding utf8NoBOM
$log=Assert-UsbDestination $Root "$Root\logs\$RunName.log"
$binary=if($UseUncompressed){"$Root\analysis\nso\main-uncompressed.nso"}else{"$Root\unpacked\effective\exefs\main"}
if ($UseUncompressed -and (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968') { throw 'Verified decompressed NSO required' }
$metadata="$Root\unpacked\effective\romfs\Data\Managed\Metadata\global-metadata.dat"
$hashes=@{}
foreach ($path in @($tool,$binary,$metadata,$configPath)) { $hashes[$path.Substring($Root.Length+1)]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
$timer=[Diagnostics.Stopwatch]::StartNew()
& $tool --binary $binary --metadata $metadata --output $output --config $configPath --cs --no-pseudo-prompt --method-body-mode csharp --pseudo-include-type AdvLog --pseudo-include-type VersionContainer --pseudo-include-type UnityEngine.Vector3 *> $log
$code=$LASTEXITCODE
$timer.Stop()
@{status=if($code -eq 0){'OUTPUT_GENERATED_NOT_VALIDATED'}else{'PROBE_FAILED'};exit_code=$code;
 upstream=$sourceLock.upstream;commit=$sourceLock.commit;elapsed_seconds=$timer.Elapsed.TotalSeconds;
 output=$output;log=$log;sha256=$hashes;verified_uncompressed_input=[bool]$UseUncompressed;experimental_nso_mapping=[bool]$UseNsoMappingFix;
 scope='Independent ARM64 pipeline with explicit source/hash gates; optional isolated NSO mapping correction is recorded. Requested type filters did not restrict the upstream CIL generation path in v3. Tool grading is not an independent native comparison or source-build/portability proof.'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\$RunName.json")
Get-Content -LiteralPath $log -Tail 16
if ($code -ne 0) { throw "Rust IL2CPP probe failed: $code; exact log preserved" }
