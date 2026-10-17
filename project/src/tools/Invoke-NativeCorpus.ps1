param([int]$MaximumNewFunctions = 30000,
 [string]$Targets = 'analysis\nso\native-targets.json',
 [string]$OutputFolder = 'analysis\nso\native-corpus',
 [int]$TimeoutSeconds = 30,
 [string]$Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [string]$JavaHome = 'C:\Program Files\Java\jdk-26.0.2',
 [switch]$RequireComplete)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
$null=Assert-UsbSpace $Root 8GB
$targetPath=Assert-UsbDestination $Root (Join-Path $Root $Targets)
$outputPath=Assert-UsbDestination $Root (Join-Path $Root $OutputFolder)
if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 300) { throw 'Timeout must be 1..300 seconds' }
if (-not (Test-Path -LiteralPath "$JavaHome\bin\javac.exe")) { throw 'An existing supported full JDK is required' }
$env:JAVA_HOME=$JavaHome
$env:GHIDRA_HEADLESS_MAXMEM='1600M'
$env:GHIDRA_HEADLESS_JAVA_OPTIONS="-Dapplication.settingsdir=$Root\cache\ghidra-settings -Dapplication.cachedir=$Root\cache\ghidra-cache -Dapplication.tempdir=$Root\cache\ghidra-temp -Dsf2.root=$Root"
$stamp=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$log=Assert-UsbDestination $Root "$Root\logs\native-corpus-$stamp.log"
$console=Assert-UsbDestination $Root "$Root\logs\native-corpus-$stamp-console.log"
& "$Root\tools\ghidra\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat" "$Root\analysis\nso" SF2-effective -process main -noanalysis -max-cpu 2 -scriptPath "$Root\src\re\tools" -postScript ExportNativeCorpus.java $targetPath $outputPath $MaximumNewFunctions $TimeoutSeconds -log $log *> $console
$code=$LASTEXITCODE
@{exit_code=$code;utc=[DateTime]::UtcNow.ToString('o');maximum_new_functions=$MaximumNewFunctions;log=$log;console=$console;scope='Pseudocode/disassembly generation; semantic coverage tracked separately'} | ConvertTo-Json | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\logs\native-corpus-$stamp-result.json")
if ($code -ne 0 -or (Select-String -LiteralPath $console -Pattern 'Error running script|SCRIPT ERROR|error: cannot find symbol' -Quiet)) { throw "Native corpus failed; inspect $console" }
$progress=Get-Content -LiteralPath "$outputPath\progress.json" -Raw | ConvertFrom-Json
if ($null -eq $progress.PSObject.Properties['failed_records'] -or $progress.failed_records -ne 0) { throw "Native records failed export-status gate; preserve corpus and inspect $console" }
if ($RequireComplete -and $progress.completed_records -ne $progress.total_targets) { throw 'Native export stopped before completing the selected batch' }
Get-Content -LiteralPath $console -Tail 5
