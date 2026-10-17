param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [Parameter(Mandatory=$true)][string]$RunName)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid recovery run' }
$output=Assert-UsbDestination $Root "$Root\analysis\il2cpp\scoped-source-build-$RunName"
if (Test-Path -LiteralPath $output) { throw 'Preserve prior scoped source experiment' }
New-Item -ItemType Directory -Path $output | Out-Null
$assembly=Assert-UsbDestination $Root "$Root\analysis\il2cpp\cpp2il-recovery-$RunName\Assembly-CSharp-firstpass.dll"
$exports=@()
foreach ($type in @('BestHTTP.Authentication.AuthenticationTypes','BestHTTP.Authentication.Credentials')) {
 $folder=Assert-UsbDestination $Root "$output\$type"
 & "$Root\tools\ilspycmd\ilspycmd.exe" -t $type -o $folder $assembly *> "$Root\logs\scoped-source-export-$RunName-$type.log"
 $exports+=@{type=$type;exit_code=$LASTEXITCODE}
}
if (@($exports | Where-Object exit_code -NE 0).Count) { throw 'Scoped source export failed; preserve exact logs' }
$project=Assert-UsbDestination $Root "$output\RecoveredScope.csproj"
@'
<Project Sdk="Microsoft.NET.Sdk">
 <PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Library</OutputType>
 <AssemblyName>RecoveredScope</AssemblyName><ImplicitUsings>disable</ImplicitUsings><Nullable>disable</Nullable>
 <GenerateAssemblyInfo>false</GenerateAssemblyInfo><GenerateTargetFrameworkAttribute>false</GenerateTargetFrameworkAttribute>
 <NuGetAudit>false</NuGetAudit><EnableNETAnalyzers>false</EnableNETAnalyzers></PropertyGroup>
</Project>
'@ | Set-Content -LiteralPath $project -Encoding utf8
dotnet restore $project --source "$Root\cache\nuget" --ignore-failed-sources --property:NuGetAudit=false *> "$Root\logs\scoped-source-restore-$RunName.log"
$restoreCode=$LASTEXITCODE;$buildCode=$null
if ($restoreCode -eq 0) {
 dotnet build $project -c Release --no-restore --maxcpucount:1 --nodeReuse:false *> "$Root\logs\scoped-source-build-$RunName.log"
 $buildCode=$LASTEXITCODE
}
$sources=@()
foreach ($source in (Get-ChildItem -LiteralPath $output -Recurse -Filter '*.cs' | Where-Object { $_.FullName -notmatch '\\obj\\' })) {
 $text=Get-Content -LiteralPath $source.FullName -Raw
 $sources+=@{path=$source.FullName;sha256=(Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant();recovery_helper_calls=([regex]::Matches($text,'NoteDecompilerIssue\(')).Count;operand_warning_comments=([regex]::Matches($text,'//IL_')).Count}
}
$status=if ($restoreCode -eq 0 -and $buildCode -eq 0) { 'PASS_TWO_TYPE_SOURCE_COMPILATION_ONLY' } else { 'SCOPED_SOURCE_COMPILATION_FAILED' }
$report=@{status=$status;recovery_run=$RunName;exports=$exports;restore_exit_code=$restoreCode;build_exit_code=$buildCode;sources=$sources;
 scope='Compiles the actual ILSpy exports of Credentials and AuthenticationTypes without source edits, external packages, recovered DLL references or replacement method bodies. This is a two-type source recovery/compiler experiment, not whole-game source, executable gameplay or semantic parity.'}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\scoped-source-build-$RunName.json") -Encoding utf8
Write-Output "$RunName : $status"
