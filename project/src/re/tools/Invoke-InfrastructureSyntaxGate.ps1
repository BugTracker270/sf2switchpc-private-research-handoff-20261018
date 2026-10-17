param([string]$Root = 'F:\SF2SwitchPC',[ValidatePattern('^[a-z0-9-]+$')][string]$ReportLabel='v32')
$ErrorActionPreference = 'Stop'
. (Join-Path $Root 'src/tools/UsbBoundary.ps1')
$Root = Assert-UsbRoot $Root
$sf2PSRows = [Collections.Generic.List[object]]::new()
$sf2PSFiles = @(& rg --files --hidden --no-ignore -g '*.ps1' -g '*.psm1' -g '*.psd1' (Join-Path $Root 'src/tools') (Join-Path $Root 'src/re/tools'))
foreach ($sf2PSFile in $sf2PSFiles) {
    $sf2Tokens = $null
    $sf2ParseIssues = $null
    [void][Management.Automation.Language.Parser]::ParseFile($sf2PSFile, [ref]$sf2Tokens, [ref]$sf2ParseIssues)
    $sf2PSRows.Add(@{
        path = [IO.Path]::GetRelativePath($Root, $sf2PSFile).Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $sf2PSFile -Algorithm SHA256).Hash.ToLowerInvariant()
        passed = ($sf2ParseIssues.Count -eq 0)
        errors = @($sf2ParseIssues | ForEach-Object { @{message=$_.Message;line=$_.Extent.StartLineNumber} })
    })
}
$sf2PSFails = @($sf2PSRows | Where-Object { -not $_.passed }).Count
$sf2PSReport = @{
    status = $(if ($sf2PSFails -eq 0) { 'PASS_ORIGINAL_POWERSHELL_SYNTAX' } else { 'FAIL_ORIGINAL_POWERSHELL_SYNTAX' })
    files = $sf2PSFiles.Count
    failures = $sf2PSFails
    source_execution = $false
    tests = $sf2PSRows
}
$sf2PSReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Assert-UsbDestination $Root (Join-Path $Root "reports/${ReportLabel}-infrastructure-powershell-syntax.json"))
Write-Output "PowerShell syntax: $($sf2PSFiles.Count - $sf2PSFails)/$($sf2PSFiles.Count) files; $sf2PSFails errors"
if ($sf2PSFails -ne 0) { exit 1 }
