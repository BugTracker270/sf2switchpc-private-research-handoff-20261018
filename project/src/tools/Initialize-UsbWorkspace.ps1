param([string]$Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'))
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\UsbBoundary.ps1"
$Root = Assert-UsbRoot $Root
$directories = @('input/base','input/update','input/reference','originals_manifest','tools','refs',
 'unpacked/nsp_pfs0/base','unpacked/nsp_pfs0/update','unpacked/base','unpacked/update','unpacked/effective',
 'analysis/nso','analysis/il2cpp','analysis/assets','analysis/reference','unity','src/tools','src/re/tools','tests',
 'build','dist','reports/performance','logs','cache/temp','cache/pip','cache/nuget','cache/npm','cache/gradle',
 'cache/dotnet','cache/python','cache/java','cache/xdg','cache/nuget-http','cache/nuget-scratch',
 'cache/nuget-plugins','cache/dotnet-bundles','cache/ghidra-settings','cache/ghidra-cache','cache/ghidra-temp','cache/cargo','backups','.codex')
foreach ($relative in $directories) {
    $destination = Assert-UsbDestination $Root (Join-Path $Root $relative)
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
}
$env:TEMP = Join-Path $Root 'cache\temp'
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP
$env:PIP_CACHE_DIR = Join-Path $Root 'cache\pip'
$env:NUGET_PACKAGES = Join-Path $Root 'cache\nuget'
$env:NUGET_HTTP_CACHE_PATH = Join-Path $Root 'cache\nuget-http'
$env:NUGET_SCRATCH = Join-Path $Root 'cache\nuget-scratch'
$env:NUGET_PLUGINS_CACHE_PATH = Join-Path $Root 'cache\nuget-plugins'
$env:npm_config_cache = Join-Path $Root 'cache\npm'
$env:CARGO_HOME = Join-Path $Root 'cache\cargo'
$env:GRADLE_USER_HOME = Join-Path $Root 'cache\gradle'
$env:DOTNET_CLI_HOME = Join-Path $Root 'cache\dotnet'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_BUNDLE_EXTRACT_BASE_DIR = Join-Path $Root 'cache\dotnet-bundles'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:PYTHONPYCACHEPREFIX = Join-Path $Root 'cache\python'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:JAVA_TOOL_OPTIONS = "-Djava.io.tmpdir=$Root\cache\java -Duser.home=$Root\cache\java"
$env:XDG_CACHE_HOME = Join-Path $Root 'cache\xdg'
$env:GIT_TERMINAL_PROMPT = '0'
$env:GIT_LFS_SKIP_SMUDGE = '1'
$destinations = [ordered]@{root=$Root; directories=$directories; caches=[ordered]@{
 TEMP=$env:TEMP; TMP=$env:TMP; TMPDIR=$env:TMPDIR; PIP_CACHE_DIR=$env:PIP_CACHE_DIR;
 NUGET_PACKAGES=$env:NUGET_PACKAGES; NUGET_HTTP_CACHE_PATH=$env:NUGET_HTTP_CACHE_PATH;
 NUGET_SCRATCH=$env:NUGET_SCRATCH;NUGET_PLUGINS_CACHE_PATH=$env:NUGET_PLUGINS_CACHE_PATH;
 DOTNET_BUNDLE_EXTRACT_BASE_DIR=$env:DOTNET_BUNDLE_EXTRACT_BASE_DIR;npm_config_cache=$env:npm_config_cache;CARGO_HOME=$env:CARGO_HOME;
 GRADLE_USER_HOME=$env:GRADLE_USER_HOME; DOTNET_CLI_HOME=$env:DOTNET_CLI_HOME;
 PYTHONPYCACHEPREFIX=$env:PYTHONPYCACHEPREFIX; XDG_CACHE_HOME=$env:XDG_CACHE_HOME}}
$configPath = Assert-UsbDestination $Root (Join-Path $Root 'reports\workspace-paths.json')
$destinations | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $configPath -Encoding utf8
$free = Assert-UsbSpace $Root 5GB
Write-Output "USB workspace initialized: $Root; $([Math]::Round($free/1GB,2)) GiB free"
Write-Output 'Process-scoped caches set. Dot-source this script in every new shell. Host profiles and CODEX_HOME unchanged.'
