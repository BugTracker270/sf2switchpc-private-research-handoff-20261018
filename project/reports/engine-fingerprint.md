# Engine fingerprint — verified local inputs

Unity **2018.1.9f1**, **IL2CPP metadata v24**, **AARCH64:LE:64:v8A**.

| Evidence | Observation |
|---|---|
| effective/romfs/Data/globalgamemanagers | Serialized v17 header; Unity version marker in header |
| effective/romfs/Data/Managed/Metadata/global-metadata.dat | 0xFAB11BAF, version 24; 11230672 bytes |
| effective/exefs/main | NSO0; Ghidra Switch Loader confirms ARM64 at 0x7100000000 |
| base CNMT | 0100AB000ABFE000, version 0; every listed content hash/size matches supplied NCAs |
| patch CNMT | 0100AB000ABFE800, version 131072; every listed content hash/size matches supplied NCAs |
| patch control.nacp +0x3060 | Display version 1.1.0 |

Decrypted CNMT contains 3 base entries and 7 patch entries. The patch includes four delta fragments; the Program patch is applied against its base through hactool, not concatenated or treated as standalone RomFS.

Effective output: 44 files, including ten level files. Exact hashes, sources and base/patch relationships: reports/extract-manifest.json. All six extraction operations returned 0, produced actual files and reported no signature failures. Full source NSP hashes: originals_manifest/inputs.json.

Il2CppDumper generated metadata schemas and 90,105 method records / 83,673 distinct native RVAs. All method RVAs lie within main's NSO text segment. Registration candidates: code 0x3925210 and metadata 0x3925280 (RVAs). Native caller validation remains pending; these are not recovered original C# implementations.

Detailed module build IDs and section layouts: engine-fingerprint.json. Ghidra memory map and all 658 imports: analysis/nso/main-memory.json. Scene names, object references and backend-specific fields are still being catalogued. AssetRipper's folder-only importer reports Unknown scripting backend; this is a tool detection limitation, not contrary engine evidence.

Full reverse engineering: **INCOMPLETE**. Combat semantics, animation timing, progression, saves and Switch-only multiplayer are not certified by metadata/extraction success.
