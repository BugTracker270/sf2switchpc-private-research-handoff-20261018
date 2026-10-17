param([string]$Root=(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'SF2SwitchPC'))
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Initialize-UsbWorkspace.ps1" -Root $Root
$path=Assert-UsbDestination $Root "$Root\cache\temp\usb-io-benchmark-$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')).bin"
$buffer=[byte[]]::new(4MB); [Random]::new(9).NextBytes($buffer)
$stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
try {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    1..8 | ForEach-Object {$stream.Write($buffer,0,$buffer.Length)}
    $stream.Flush($true);$watch.Stop();$write=$watch.Elapsed.TotalSeconds
    $stream.Position=0;$watch.Restart()
    while($stream.Read($buffer,0,$buffer.Length) -gt 0){}
    $watch.Stop();$read=$watch.Elapsed.TotalSeconds
    $sample=[byte[]]::new(4096);$random=[Random]::new(7);$latencies=@()
    1..16 | ForEach-Object {
        $stream.Position=$random.Next(0,8192)*4096L;$watch.Restart()
        $stream.Write($sample,0,$sample.Length);$stream.Flush($true);$watch.Stop()
        $latencies+=$watch.Elapsed.TotalMilliseconds
    }
} finally {$stream.Dispose()}
@{utc=[DateTime]::UtcNow.ToString('o');bytes=32MB;sequential_write_seconds=$write;
  sequential_write_mib_per_s=32/$write;warm_read_seconds=$read;warm_read_mib_per_s=32/$read;
  random_4k_flush_ms=$latencies;concurrent_analysis=$true;
  notes='WriteThrough and Flush(true); OS/USB controller caching may remain. Read is warm-cache. Other analysis was running. These are workload-specific I/O measurements, not game FPS.';
  retained_test_file=$path} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Assert-UsbDestination $Root "$Root\reports\usb-io.json")
Get-Content -LiteralPath "$Root\reports\usb-io.json" -Raw
