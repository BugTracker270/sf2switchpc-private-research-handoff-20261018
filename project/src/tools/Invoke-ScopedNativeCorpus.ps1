param([Parameter(Mandatory)][string]$Name,
 [string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [string]$JavaHome='C:\Program Files\Java\jdk-26.0.2')
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($Name -notmatch '^[a-z0-9-]+$') { throw 'Invalid scope name' }
$targets=Assert-UsbDestination $Root "$Root\analysis\nso\$Name-targets.json"
$metadata=Assert-UsbDestination $Root "$Root\analysis\nso\$Name-metadata.json"
$archive=Assert-UsbDestination $Root "$Root\analysis\il2cpp\sf2-arm64-types-layout-v2.gdt"
$output=Assert-UsbDestination $Root "$Root\analysis\nso\typed-$Name"
$console=Assert-UsbDestination $Root "$Root\logs\ghidra-$Name-console.log"
foreach ($inputFile in @($targets,$metadata,$archive)) { if (-not (Test-Path -LiteralPath $inputFile)) { throw "Missing scope input: $inputFile" } }
$env:JAVA_HOME=$JavaHome
$env:GHIDRA_HEADLESS_MAXMEM='1500M'
$env:GHIDRA_HEADLESS_JAVA_OPTIONS="-Dapplication.settingsdir=$Root\cache\ghidra-settings -Dapplication.cachedir=$Root\cache\ghidra-cache -Dapplication.tempdir=$Root\cache\ghidra-temp -Dsf2.root=$Root"
& "$Root\tools\ghidra\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat" "$Root\analysis\nso" SF2-effective -process main -noanalysis -max-cpu 2 -scriptPath "$Root\src\re\tools" -postScript ApplyScopedTypes.java $archive $targets $metadata -postScript ExportNativeCorpus.java $targets $output 10000 120 -log "$Root\logs\ghidra-$Name.log" *> $console
$code=$LASTEXITCODE
@{exit_code=$code;utc=[DateTime]::UtcNow.ToString('o');console=$console;archive=$archive} | ConvertTo-Json | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\logs\ghidra-$Name-result.json")
if ($code -ne 0 -or (Select-String -LiteralPath $console -Pattern 'Error running script|SCRIPT ERROR|error: cannot find symbol' -Quiet)) { throw 'Scoped native pass failed; inspect console' }
$progress=Get-Content -LiteralPath "$output\progress.json" -Raw | ConvertFrom-Json
if ($null -eq $progress.PSObject.Properties['failed_records'] -or $progress.failed_records -ne 0) { throw 'Scoped native records failed export gate; inspect preserved corpus' }
$application=Get-Content -LiteralPath "$Root\analysis\nso\scoped-type-application.json" -Raw | ConvertFrom-Json
Copy-Item -LiteralPath "$Root\analysis\nso\scoped-type-application.json" -Destination (Assert-UsbDestination $Root "$Root\analysis\nso\$Name-type-application.json")
if (@($application.errors).Count -ne 0) { throw 'Type application had errors; scope report preserved' }
Get-Content -LiteralPath $console -Tail 5
