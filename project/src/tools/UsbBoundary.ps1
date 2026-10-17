Set-StrictMode -Version Latest

function Assert-UsbRoot {
    param([Parameter(Mandatory)][string]$Root)
    if ($Root -match '(^|[\\/])\.\.([\\/]|$)') { throw 'Traversal in root' }
    $full = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ($full -notmatch '^[A-Za-z]:\\SF2SwitchPC$') { throw 'Root must be <USB>:\SF2SwitchPC' }
    $disk = Get-Partition -DriveLetter $full.Substring(0,1) -ErrorAction Stop | Get-Disk
    if (@($disk).Count -ne 1 -or $disk.BusType -ne 'USB' -or $disk.IsReadOnly) { throw 'Writable USB provenance required' }
    Assert-NoReparse $full
    return $full
}

function Assert-NoReparse {
    param([string]$Path)
    $cursor = $Path
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point forbidden: $cursor" }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-UsbDestination {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)
    $canonical = Assert-UsbRoot $Root
    if ($Path -notmatch '^[A-Za-z]:[\\/]') { throw 'Absolute drive-qualified output path required' }
    if ($Path -match '(^|[\\/])\.\.([\\/]|$)' -or $Path -match '[\x00-\x1f]') { throw 'Invalid output path' }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($canonical + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Output outside USB root: $full" }
    if ($full.Substring(2).Contains(':')) { throw 'Alternate stream forbidden' }
    Assert-NoReparse $full
    return $full
}

function Assert-UsbSpace {
    param([string]$Root, [long]$RequiredBytes = 5GB)
    $canonical = Assert-UsbRoot $Root
    $volume = Get-Volume -DriveLetter $canonical.Substring(0,1)
    if ($volume.SizeRemaining -lt $RequiredBytes) { throw "Insufficient USB space; require $RequiredBytes bytes" }
    return $volume.SizeRemaining
}
