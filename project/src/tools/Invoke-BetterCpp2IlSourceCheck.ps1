param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [string]$RunName='better-source-v1',[string]$ReferenceRun='nso-bool-fields-v19')
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($RunName -notmatch '^[a-z0-9-]+$' -or $ReferenceRun -notmatch '^[a-z0-9-]+$') { throw 'Invalid run' }
$source=Assert-UsbDestination $Root "$Root\analysis\il2cpp\$RunName\CSharpSource"
$output=Assert-UsbDestination $Root "$Root\analysis\il2cpp\$RunName-compile"
if (Test-Path -LiteralPath $output) { throw 'Preserve compiler evidence' }
$legacy=@{}
$lock=Get-Content -LiteralPath "$Root\reports\legacy-reference-assemblies-lock.json" -Raw | ConvertFrom-Json
if ($lock.status -ne 'PASS_OFFICIAL_CATALOG_PACKAGE_SHA512') { throw 'Verified reference package required' }
foreach ($reference in $lock.files) {
 $path=Assert-UsbDestination $Root (Join-Path $Root $reference.path)
 if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $reference.sha256) { throw 'Reference integrity failure' }
 $name=[IO.Path]::GetFileName($path)
 if (-not $legacy.ContainsKey($name) -or $path.Length -lt $legacy[$name].Length) { $legacy[$name]=$path }
}
$results=@()
foreach ($directory in Get-ChildItem -LiteralPath $source -Directory) {
 if (@(Get-ChildItem -LiteralPath $directory.FullName -Recurse -Filter '*.cs').Count -eq 0) { continue }
 $name=$directory.Name
 $folder=Assert-UsbDestination $Root "$output\$name"
 New-Item -ItemType Directory -Path $folder | Out-Null
 $references=@()
 foreach ($dll in Get-ChildItem -LiteralPath "$Root\analysis\il2cpp\cpp2il-recovery-$ReferenceRun" -Filter '*.dll') {
  if ($dll.BaseName -eq $name) { continue }
  $path=if ($legacy.ContainsKey($dll.Name)){$legacy[$dll.Name]}else{$dll.FullName}
  $references+="<Reference Include=`"$([Security.SecurityElement]::Escape($dll.BaseName))`"><HintPath>$([Security.SecurityElement]::Escape($path))</HintPath><Private>false</Private></Reference>"
 }
 $inputs=[Security.SecurityElement]::Escape("$($directory.FullName)\**\*.cs")
 $project=Assert-UsbDestination $Root "$folder\Probe.csproj"
 @"
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
 <TargetFramework>net10.0</TargetFramework><AssemblyName>$name</AssemblyName><OutputType>Library</OutputType>
 <NoStdLib>true</NoStdLib><DisableImplicitFrameworkReferences>true</DisableImplicitFrameworkReferences>
 <EnableDefaultCompileItems>false</EnableDefaultCompileItems><GenerateAssemblyInfo>false</GenerateAssemblyInfo>
 <GenerateTargetFrameworkAttribute>false</GenerateTargetFrameworkAttribute><ImplicitUsings>disable</ImplicitUsings>
 <AllowUnsafeBlocks>true</AllowUnsafeBlocks><LangVersion>latest</LangVersion><NuGetAudit>false</NuGetAudit>
 <EnableNETAnalyzers>false</EnableNETAnalyzers></PropertyGroup>
 <ItemGroup><Compile Include="$inputs" />$($references -join "`n")</ItemGroup></Project>
"@ | Set-Content -LiteralPath $project -Encoding utf8
 $log=Assert-UsbDestination $Root "$Root\logs\$RunName-compile-$name.log"
 dotnet build $project -c Release --source "$Root\cache\nuget" --ignore-failed-sources --maxcpucount:1 --nodeReuse:false *> $log
 $code=$LASTEXITCODE
 $diagnostics=@(Get-Content -LiteralPath $log | Where-Object { $_ -match '\berror CS[0-9]+:' } | Sort-Object -Unique)
 $counts=@{}
 foreach ($line in $diagnostics) { if ($line -match '\berror (CS[0-9]+):') { $counts[$Matches[1]]++ } }
 $files=@(Get-ChildItem -LiteralPath $directory.FullName -Recurse -Filter '*.cs' | ForEach-Object {
  @{path=$_.FullName.Substring($Root.Length+1);sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
 })
 $results+=@{assembly=$name;exit_code=$code;unique_diagnostic_lines=$diagnostics.Count;error_codes=$counts;source_files=$files;log=$log.Substring($Root.Length+1)}
 Write-Output "$name unchanged alternative source build=$code diagnostics=$($diagnostics.Count)"
}
@{status=if(@($results | Where-Object exit_code -NE 0).Count){'SOURCE_PROBE_BUILD_FAILED'}else{'PASS_SCOPED_SOURCE_COMPILATION_ONLY'};
 run=$RunName;reference_run=$ReferenceRun;assemblies=$results;
 scope='Unchanged alternative-tool source with verified official legacy framework references and matching metadata-derived dependency assemblies. Parser errors precede reference binding. No gameplay, complete-source or semantic claim.'
} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\$RunName-compile.json")
