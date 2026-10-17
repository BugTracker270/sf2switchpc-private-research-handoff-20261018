param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [Parameter(Mandatory=$true)][string]$RunName,[switch]$UseLegacyReferenceAssemblies,
 [ValidateSet('source-project-build','source-profile-project-build')][string]$SourceKind='source-project-build')
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($RunName -notmatch '^[a-z0-9-]+$') { throw 'Invalid recovery run' }
$source=Assert-UsbDestination $Root "$Root\analysis\il2cpp\$SourceKind-$RunName"
$assemblies=Assert-UsbDestination $Root "$Root\analysis\il2cpp\cpp2il-recovery-$RunName"
$kind=if ($UseLegacyReferenceAssemblies) { 'source-legacy-reference-check' } else { 'source-reference-check' }
$logPrefix=if ($UseLegacyReferenceAssemblies) { 'source-legacy-reference' } else { 'source-reference' }
if ($SourceKind -eq 'source-profile-project-build') {
 if (-not $UseLegacyReferenceAssemblies) { throw 'Profile-source experiment requires explicit legacy reference selection' }
 $kind='source-profile-legacy-reference-check';$logPrefix='source-profile-legacy-reference'
}
$output=Assert-UsbDestination $Root "$Root\analysis\il2cpp\$kind-$RunName"
if (Test-Path -LiteralPath $output) { throw 'Preserve previous matching-reference experiment' }
if (-not (Test-Path -LiteralPath "$source\result.json")) { throw 'Completed project-export experiment required' }
New-Item -ItemType Directory -Path $output | Out-Null
$legacy=@{}
if ($UseLegacyReferenceAssemblies) {
 $lock=Get-Content -LiteralPath "$Root\reports\legacy-reference-assemblies-lock.json" -Raw | ConvertFrom-Json
 if ($lock.status -ne 'PASS_OFFICIAL_CATALOG_PACKAGE_SHA512') { throw 'Official reference-package integrity gate required' }
 foreach ($reference in $lock.files) {
  $referencePath=Assert-UsbDestination $Root (Join-Path $Root $reference.path)
  if ((Get-FileHash -LiteralPath $referencePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $reference.sha256) { throw 'Reference DLL digest mismatch' }
  $referenceName=[IO.Path]::GetFileName($referencePath)
  if (-not $legacy.ContainsKey($referenceName) -or $referencePath.Length -lt $legacy[$referenceName].Length) { $legacy[$referenceName]=$referencePath }
 }
}
$results=@()
foreach ($name in @('Assembly-CSharp-firstpass','Assembly-CSharp')) {
 $folder=Assert-UsbDestination $Root "$output\$name"
 New-Item -ItemType Directory -Path $folder | Out-Null
 $references=@()
 $referencePaths=@()
 foreach ($dependency in (Get-ChildItem -LiteralPath $assemblies -Filter '*.dll')) {
  if ($dependency.BaseName -eq $name) { continue }
  $include=[Security.SecurityElement]::Escape($dependency.BaseName)
  $referencePath=if ($UseLegacyReferenceAssemblies -and $legacy.ContainsKey($dependency.Name)) { $legacy[$dependency.Name] } else { $dependency.FullName }
  $hint=[Security.SecurityElement]::Escape($referencePath)
  $referencePaths+=@{assembly=$dependency.BaseName;path=$referencePath;official_legacy_reference=($referencePath -ne $dependency.FullName)}
  $references+="<Reference Include=`"$include`"><HintPath>$hint</HintPath><Private>false</Private></Reference>"
 }
 $inputs=[Security.SecurityElement]::Escape("$source\$name\**\*.cs")
 $exclude=[Security.SecurityElement]::Escape("$source\$name\obj\**;$source\$name\bin\**")
 $project=Assert-UsbDestination $Root "$folder\MatchingReferences.csproj"
 @"
<Project Sdk="Microsoft.NET.Sdk">
 <PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Library</OutputType><AssemblyName>$name</AssemblyName>
 <NoStdLib>true</NoStdLib><DisableImplicitFrameworkReferences>true</DisableImplicitFrameworkReferences>
 <EnableDefaultCompileItems>false</EnableDefaultCompileItems><GenerateAssemblyInfo>false</GenerateAssemblyInfo>
 <GenerateTargetFrameworkAttribute>false</GenerateTargetFrameworkAttribute><ImplicitUsings>disable</ImplicitUsings>
 <Nullable>disable</Nullable><AllowUnsafeBlocks>true</AllowUnsafeBlocks><LangVersion>latest</LangVersion>
 <NuGetAudit>false</NuGetAudit><EnableNETAnalyzers>false</EnableNETAnalyzers></PropertyGroup>
 <ItemGroup><Compile Include="$inputs" Exclude="$exclude" />$($references -join "`n")</ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $project -Encoding utf8
 dotnet restore $project --source "$Root\cache\nuget" --ignore-failed-sources --property:NuGetAudit=false *> "$Root\logs\$logPrefix-restore-$RunName-$name.log"
 $restoreCode=$LASTEXITCODE;$buildCode=$null
 if ($restoreCode -eq 0) {
  dotnet build $project -c Release --no-restore --maxcpucount:1 --nodeReuse:false --verbosity:normal *> "$Root\logs\$logPrefix-build-$RunName-$name.log"
  $buildCode=$LASTEXITCODE
 }
 $results+=@{assembly=$name;export_exit_code=0;restore_exit_code=$restoreCode;build_exit_code=$buildCode;folder="$source\$name";references=$referencePaths;compiler_log="logs/$logPrefix-build-$RunName-$name.log"}
 Write-Output "$name matching-reference restore=$restoreCode build=$buildCode"
}
$status=if (@($results | Where-Object { $_.restore_exit_code -ne 0 -or $_.build_exit_code -ne 0 }).Count) { 'SOURCE_BUILD_LIMITATIONS_CONFIRMED' } else { 'PASS_MATCHING_METADATA_SOURCE_COMPILATION_ONLY' }
@{status=$status;run=$RunName;experiment=$kind;official_legacy_framework_references=[bool]$UseLegacyReferenceAssemblies;assemblies=$results;scope='Diagnostic compiler check of unchanged project-export source, with standard-library/framework injection disabled and every explicit reference recorded. Optional official unstripped .NET 3.5 references replace matching supplied framework assembly names. The compiler runs on .NET 10, but its ordinary reference pack is excluded. This does not certify portable runtime implementation, clean helper-free bodies, full attributes or gameplay.'} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$output\result.json") -Encoding utf8
python "$Root\src\re\tools\summarize_source_build.py" --run $RunName --kind $kind
if ($LASTEXITCODE -ne 0) { throw 'Matching-reference summary failed' }
