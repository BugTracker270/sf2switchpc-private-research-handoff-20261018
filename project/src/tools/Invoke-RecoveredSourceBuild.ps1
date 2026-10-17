param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [Parameter(Mandatory=$true)][string]$RunName,[switch]$ProjectExport,[switch]$PreserveAnonymousTypes,[switch]$UseLegacyDecompilerReferences)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid recovery run' }
$assemblies=Assert-UsbDestination $Root "$Root\analysis\il2cpp\cpp2il-recovery-$RunName"
$kind=if ($UseLegacyDecompilerReferences) { 'source-profile-project-build' } elseif ($ProjectExport) { 'source-project-build' } else { 'source-build' }
$logPrefix=if ($UseLegacyDecompilerReferences) { 'source-profile-project' } elseif ($ProjectExport) { 'source-project' } else { 'source' }
if ($UseLegacyDecompilerReferences -and -not $ProjectExport) { throw 'Legacy decompiler resolution view requires project export' }
$decompilerInputs=$assemblies
if ($UseLegacyDecompilerReferences) {
 python "$Root\src\re\tools\prepare_decompiler_reference_view.py" --run $RunName *> "$Root\logs\decompiler-reference-view-$RunName.log"
 if ($LASTEXITCODE -ne 0) { throw 'Decompiler reference preparation failed' }
 $decompilerInputs=Assert-UsbDestination $Root "$Root\analysis\il2cpp\decompiler-reference-view-$RunName"
}
$output=Assert-UsbDestination $Root "$Root\analysis\il2cpp\$kind-$RunName"
if (Test-Path -LiteralPath $output) { throw 'Preserve previous source-build experiment' }
New-Item -ItemType Directory -Path $output | Out-Null
$results=@()
foreach ($name in @('Assembly-CSharp-firstpass','Assembly-CSharp')) {
 $folder=Assert-UsbDestination $Root "$output\$name"
 New-Item -ItemType Directory -Path $folder | Out-Null
 $dll=Assert-UsbDestination $Root "$decompilerInputs\$name.dll"
 if (-not (Test-Path -LiteralPath $dll)) { throw "Missing recovered assembly: $name" }
 $exportLog=Assert-UsbDestination $Root "$Root\logs\$logPrefix-export-$RunName-$name.log"
 $exportArguments=@('--disable-updatecheck','-o',$folder,'-r',$decompilerInputs)
 if ($ProjectExport) { $exportArguments+=@('-p','--nested-directories') }
 if ($PreserveAnonymousTypes) { $exportArguments+=@('--decompiler-setting','AnonymousTypes=false') }
 & "$Root\tools\ilspycmd\ilspycmd.exe" @exportArguments $dll *> $exportLog
 $exportCode=$LASTEXITCODE
 $restoreCode=$null; $buildCode=$null
 if ($exportCode -eq 0) {
  $references=@()
  foreach ($dependency in (Get-ChildItem -LiteralPath $assemblies -Filter '*.dll')) {
   if ($dependency.BaseName -eq $name -or $dependency.BaseName -match '^(mscorlib|netstandard|System(?:\.|$)|Microsoft\.)') { continue }
   $include=[Security.SecurityElement]::Escape($dependency.BaseName)
   $hint=[Security.SecurityElement]::Escape($dependency.FullName)
   $references+="<Reference Include=`"$include`"><HintPath>$hint</HintPath><Private>false</Private></Reference>"
  }
  $project=Assert-UsbDestination $Root "$folder\RecoveredSource.csproj"
  $xml=@"
<Project Sdk="Microsoft.NET.Sdk">
 <PropertyGroup>
  <TargetFramework>net10.0</TargetFramework><OutputType>Library</OutputType>
  <AssemblyName>$name</AssemblyName><GenerateAssemblyInfo>false</GenerateAssemblyInfo>
  <GenerateTargetFrameworkAttribute>false</GenerateTargetFrameworkAttribute>
  <ImplicitUsings>disable</ImplicitUsings><Nullable>disable</Nullable><AllowUnsafeBlocks>true</AllowUnsafeBlocks>
  <LangVersion>latest</LangVersion><NuGetAudit>false</NuGetAudit><EnableNETAnalyzers>false</EnableNETAnalyzers>
 </PropertyGroup>
 <ItemGroup>$($references -join "`n")</ItemGroup>
</Project>
"@
  $xml | Set-Content -LiteralPath $project -Encoding utf8
  dotnet restore $project --source "$Root\cache\nuget" --ignore-failed-sources --property:NuGetAudit=false *> "$Root\logs\$logPrefix-restore-$RunName-$name.log"
  $restoreCode=$LASTEXITCODE
  if ($restoreCode -eq 0) {
   dotnet build $project -c Release --no-restore --maxcpucount:1 --nodeReuse:false *> "$Root\logs\$logPrefix-build-$RunName-$name.log"
   $buildCode=$LASTEXITCODE
  }
 }
 $results+=@{assembly=$name;export_exit_code=$exportCode;restore_exit_code=$restoreCode;build_exit_code=$buildCode;folder=$folder;compiler_log="logs/$logPrefix-build-$RunName-$name.log"}
 $state=@{run=$RunName;experiment=$kind;preserve_anonymous_type_definitions=[bool]$PreserveAnonymousTypes;utc=[DateTime]::UtcNow.ToString('o');assemblies=$results;status='IN_PROGRESS';scope='Diagnostic .NET 10 compiler check of complete game-assembly C# exports against recovered dependency metadata. Only the original infrastructure-generated RecoveredSource.csproj is executed; the decompiler-generated project is retained as evidence. This is not a Unity build, portable game, original-runtime validation or semantic completeness proof.'}
 $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$output\result.json") -Encoding utf8
 Write-Output "$name source export=$exportCode restore=$restoreCode build=$buildCode"
}
$state.status=if (@($results | Where-Object { $_.export_exit_code -ne 0 -or $_.restore_exit_code -ne 0 -or $_.build_exit_code -ne 0 }).Count) { 'SOURCE_BUILD_LIMITATIONS_CONFIRMED' } else { 'PASS_DIAGNOSTIC_SOURCE_COMPILATION_ONLY' }
$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$output\result.json") -Encoding utf8
python "$Root\src\re\tools\summarize_source_build.py" --run $RunName --kind $kind
if ($LASTEXITCODE -ne 0) { throw 'Source-build summary failed; preserve logs' }
