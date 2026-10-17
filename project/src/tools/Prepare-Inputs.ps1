param([Parameter(Mandatory)][string]$SourceFolder,
 [string]$Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'))
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
$source = [IO.Path]::GetFullPath($SourceFolder)
if ([IO.Path]::GetPathRoot($source) -ne [IO.Path]::GetPathRoot($Root)) { throw 'Inputs must be on verified USB' }
Assert-NoReparse $source
$sevenZip = 'C:\Program Files\7-Zip\7z.exe'
if (-not (Test-Path -LiteralPath $sevenZip)) { throw 'Installed 7-Zip not found' }
$manifest = [Collections.Generic.List[object]]::new()
foreach ($archive in Get-ChildItem -LiteralPath $source -Filter '*.rar' -File) {
    $kind = if ($archive.Name -match 'BASE') { 'base' } elseif ($archive.Name -match 'Update') { 'update' } else { throw 'Unclassified archive' }
    $archiveHash = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $listing = & $sevenZip l -slt $archive.FullName
    if ($LASTEXITCODE -ne 0) { throw "7-Zip listing failed: $LASTEXITCODE" }
    $listing | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\$kind-7zip-list.txt")
    $members = @($listing | Where-Object { $_ -match '^Path = .*\.nsp$' } | ForEach-Object { $_.Substring(7) })
    if ($members.Count -ne 1 -or $members[0] -match '[/\\:]' -or $members[0] -eq '..') { throw 'Expected one safe NSP member' }
    $dest = Assert-UsbDestination $Root "$Root\input\$kind"
    $nsp = Assert-UsbDestination $Root (Join-Path $dest $members[0])
    $null = Assert-UsbSpace $Root 8GB
    if (-not (Test-Path -LiteralPath $nsp)) {
        & $sevenZip e $archive.FullName $members[0] "-o$dest" -aos -bb1 2>&1 | Tee-Object -FilePath (Assert-UsbDestination $Root "$Root\logs\$kind-7zip-extract.log")
        $code = $LASTEXITCODE
        @{tool=$sevenZip;input=$archive.FullName;member=$members[0];exit_code=$code;utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath "$Root\logs\$kind-7zip-extract-result.json"
        if ($code -ne 0) { throw "7-Zip extraction failed with $code" }
    }
    $nspItem = Get-Item -LiteralPath $nsp
    $nspHash = (Get-FileHash -LiteralPath $nsp -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest.Add([ordered]@{kind=$kind;archive=$archive.FullName;archive_bytes=$archive.Length;archive_sha256=$archiveHash;
      archive_last_write_utc=$archive.LastWriteTimeUtc.ToString('o');nsp=$nsp;nsp_bytes=$nspItem.Length;nsp_sha256=$nspHash;
      nsp_last_write_utc=$nspItem.LastWriteTimeUtc.ToString('o');version_status='filename claim only; CNMT not yet parsed';
      extraction='7-Zip exact NSP member only; bundled URL not extracted';original_policy='read-only'})
    $manifest | ConvertTo-Json -Depth 5 -AsArray | Set-Content -LiteralPath "$Root\originals_manifest\inputs.json"
    Write-Output "$kind NSP SHA-256 $nspHash ($($nspItem.Length) bytes)"
}
if ($manifest.Count -ne 2) { throw 'Expected both base and update' }
