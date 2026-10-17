param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [string]$RunName='better-source-v1',
 [string]$TypeFilter='AdvLog,VersionContainer,UnityEngine.Vector3,DG.Tweening.Plugins.Vector3WrapperPlugin')
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid run name' }
$null=Assert-UsbSpace $Root 8GB
$repo="$Root\refs\BetterCpp2IL"
$pin='43850f644a1584a8ca700cab2f71f4b2462eb255'
if ((git -C $repo rev-parse HEAD) -ne $pin) { throw 'Unexpected BetterCpp2IL commit' }
if (git -C $repo status --porcelain --untracked-files=no) { throw 'Probe requires unchanged upstream source' }
$output=Assert-UsbDestination $Root "$Root\analysis\il2cpp\$RunName"
if (Test-Path -LiteralPath $output) { throw 'Preserve earlier probe output' }
$log=Assert-UsbDestination $Root "$Root\logs\$RunName.log"
$tool="$repo\src\Cpp2IL\bin\Release\net10.0\Cpp2IL.dll"
$binary="$Root\unpacked\effective\exefs\main"
$metadata="$Root\unpacked\effective\romfs\Data\Managed\Metadata\global-metadata.dat"
$hashes=@{}
foreach ($path in @($tool,"$repo\src\Cpp2IL\bin\Release\net10.0\Cpp2IL.Core.dll",$binary,$metadata)) {
 $hashes[$path.Substring($Root.Length+1)]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$timer=[Diagnostics.Stopwatch]::StartNew()
$env:DOTNET_GCHeapHardLimit='60000000'
dotnet $tool --force-binary-path $binary --force-metadata-path $metadata --force-unity-version 2018.1.9f1 --low-memory-mode --output-as csharp_source --output-to $output --type-filter $TypeFilter *> $log
$code=$LASTEXITCODE
$timer.Stop()
@{status=if($code -eq 0){'OUTPUT_GENERATED_NOT_VALIDATED'}else{'PROBE_FAILED'};exit_code=$code;
 upstream='https://github.com/smartfish67png/BetterCpp2IL';commit=$pin;license='MIT';
 type_filter=$TypeFilter;elapsed_seconds=$timer.Elapsed.TotalSeconds;output=$output;log=$log;sha256=$hashes;
 scope='Unmodified alternative C# printer on original NSO/metadata. Exit success is not source compilation, semantic validation, or a portable game.'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\$RunName.json")
Get-Content -LiteralPath $log -Tail 12
if ($code -ne 0) { throw "BetterCpp2IL probe failed: $code; exact log preserved" }
