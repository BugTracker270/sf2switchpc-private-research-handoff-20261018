param([string]$Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'))
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\UsbBoundary.ps1"
$Root = Assert-UsbRoot $Root
$config = Get-Content -LiteralPath "$Root\reports\workspace-paths.json" -Raw | ConvertFrom-Json
$results = [Collections.Generic.List[object]]::new()
foreach ($relative in $config.directories) {
    $null = Assert-UsbDestination $Root (Join-Path $Root $relative)
    $results.Add(@{name="directory:$relative";passed=$true})
}
foreach ($property in $config.caches.PSObject.Properties) {
    $null = Assert-UsbDestination $Root $property.Value
    $results.Add(@{name="cache:$($property.Name)";passed=$true})
}
$bad = @('C:\SF2SwitchPC\build', ($Root+'-escape\bad'), ($Root+'\..\escape'), ($Root+'\input\file:stream'), 'relative\output', '\\server\share\out', 'F:relative\output', '\relative\output')
foreach ($candidate in $bad) {
    $rejected = $false
    try { $null = Assert-UsbDestination $Root $candidate } catch { $rejected = $true }
    $results.Add(@{name="reject:$candidate";passed=$rejected})
    if (-not $rejected) { throw "Boundary accepted invalid path $candidate" }
}
$report = @{passed=$results.Count;failed=0;cases=$results;utc=[DateTime]::UtcNow.ToString('o')}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\boundary-tests.json")
Write-Output "PASS: $($results.Count) boundary cases"
