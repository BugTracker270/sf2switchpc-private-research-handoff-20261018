# Shadow Fight 2 Switch binary research

Private, USB-hosted research workspace. Current scope ends at decompilation and reverse engineering, before Windows implementation. Read STATUS.md for verified results and blockers. No playable port exists.

Open PowerShell here and run:

```powershell
. .\src\tools\Initialize-UsbWorkspace.ps1
& .\src\tools\Test-UsbWriteBoundary.ps1
python -m unittest discover -s tests -v
```

Original RAR archives remain at their original USB location. Extracted NSPs go under input/base and input/update. Proprietary outputs remain ignored and local. Reports distinguish filenames, unverified claims, parsed metadata and validated native evidence. No system installation or public upload is authorized.
