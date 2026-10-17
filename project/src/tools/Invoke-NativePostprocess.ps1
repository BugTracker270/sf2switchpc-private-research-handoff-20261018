param([int]$WaitForProcessId,
 [string]$TypedFolder='analysis\nso\typed-behavior-corpus',
 [string]$LogStem='ghidra-typed-behaviors',
 [string]$Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'),
 [string]$JavaHome = 'C:\Program Files\Java\jdk-26.0.2')
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
if ($WaitForProcessId -gt 0) {
    while (Get-Process -Id $WaitForProcessId -ErrorAction SilentlyContinue) { Start-Sleep -Seconds 10 }
}
python "$Root\src\re\tools\prepare_native_followup.py" *> "$Root\logs\prepare-native-followup.log"
if ($LASTEXITCODE -ne 0) { throw 'Native follow-up preparation failed; preserve corpus and inspect log' }
$repairTargets=Get-Content -LiteralPath "$Root\analysis\nso\library-repair-targets.json" -Raw | ConvertFrom-Json
if (@($repairTargets).Count -gt 0) {
    & "$PSScriptRoot\Invoke-NativeCorpus.ps1" -Root $Root -JavaHome $JavaHome -Targets 'analysis\nso\library-repair-targets.json' -OutputFolder 'analysis\nso\native-corpus-library-repairs' -MaximumNewFunctions 10000 -TimeoutSeconds 120
}
$env:JAVA_HOME=$JavaHome
$env:GHIDRA_HEADLESS_MAXMEM='1600M'
$env:GHIDRA_HEADLESS_JAVA_OPTIONS="-Dapplication.settingsdir=$Root\cache\ghidra-settings -Dapplication.cachedir=$Root\cache\ghidra-cache -Dapplication.tempdir=$Root\cache\ghidra-temp -Dsf2.root=$Root"
if ($LogStem -notmatch '^[a-z0-9-]+$') { throw 'Invalid log stem' }
$typedOutput=Assert-UsbDestination $Root (Join-Path $Root $TypedFolder)
$console=Assert-UsbDestination $Root "$Root\logs\$LogStem-console.log"
& "$Root\tools\ghidra\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat" "$Root\analysis\nso" SF2-effective -process main -noanalysis -max-cpu 2 -scriptPath "$Root\src\re\tools" -postScript ApplyScopedTypes.java "$Root\analysis\il2cpp\sf2-arm64-types-layout-v2.gdt" "$Root\analysis\nso\typed-behavior-targets.json" "$Root\analysis\nso\typed-behavior-metadata.json" -postScript ExportNativeCorpus.java "$Root\analysis\nso\typed-behavior-targets.json" $typedOutput 10000 120 -log "$Root\logs\$LogStem.log" *> $console
$code=$LASTEXITCODE
@{exit_code=$code;utc=[DateTime]::UtcNow.ToString('o');console=$console} | ConvertTo-Json | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\logs\$LogStem-result.json")
if ($code -ne 0 -or (Select-String -LiteralPath $console -Pattern 'Error running script|SCRIPT ERROR|error: cannot find symbol' -Quiet)) { throw 'Typed behavior pass failed; inspect exact console log' }
python "$Root\src\re\tools\native_corpus_index.py" --build *> "$Root\logs\native-index.log"
if ($LASTEXITCODE -ne 0) { throw 'Native corpus index failed' }
python "$Root\src\re\tools\refresh_behavior_reports.py" *> "$Root\logs\behavior-reports.log"
if ($LASTEXITCODE -ne 0) { throw 'Behavior report generation failed' }
python "$Root\src\re\tools\refresh_reports.py" *> "$Root\logs\refresh-reports.log"
if ($LASTEXITCODE -ne 0) { throw 'Progress report generation failed' }
Get-Content -LiteralPath $console -Tail 7
