using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Current=Cpp2IL.Core.Utils.LegacyArm64AllocationPattern;
using Baseline=Cpp2IL.Core.Utils.BaselineV32.LegacyArm64AllocationPattern;

if(args.Length!=1)throw new ArgumentException("Verified USB root required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return path;}
string Hash(byte[] value)=>Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
const ulong helper=0xB2E720;
var original=File.ReadAllBytes(Guard("analysis/reference/class-guard-v32-source/LegacyArm64AllocationPattern.cs"));
var baseline=File.ReadAllBytes(Guard("analysis/reference/class-guard-v32-source/LegacyArm64AllocationPattern-v32-namespaced.cs"));
if(Hash(original)!="619639e8e6f0cd092b1815365c1223f50e261758cb8db5635cbd79dbc1f1691f"||Hash(baseline)!="f5000d5ee6c68cfb73e69152f5a3ddd6fd878dc00725c75388f6431c1e5cd215")throw new IOException("Frozen v32 source differs");
var raw=File.ReadAllBytes(Guard("analysis/nso/main-uncompressed.nso"));if(Hash(raw)!="bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968")throw new IOException("Native binary differs");
uint U32(int offset)=>BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset,4));
if(U32(0x10)!=0x100||U32(0x14)!=0)throw new IOException("Unexpected original NSO text layout");ulong textEnd=U32(0x18);
var frames=new Dictionary<ulong,HashSet<ulong>>();int parsed=0;
foreach(var line in File.ReadLines(Guard("analysis/nso/unwind-inventory-v1/frames.jsonl"))){using var document=JsonDocument.Parse(line);var row=document.RootElement;ulong rva=row.GetProperty("rva").GetUInt64(),end=row.GetProperty("end_rva").GetUInt64();if(!frames.TryGetValue(rva,out var ends))frames[rva]=ends=[];ends.Add(end);parsed++;}
int oldTotal=0,newTotal=0,scanned=0,ambiguous=0,outside=0,oversized=0;var added=new List<object>();var removed=new List<object>();
foreach(var (rva,ends) in frames.OrderBy(p=>p.Key)){
    if(ends.Count!=1){ambiguous++;continue;}ulong end=ends.Single();
    if(rva%4!=0||end<=rva||(end-rva)%4!=0||end>textEnd||end+0x100>(ulong)raw.Length){outside++;continue;}
    if(end-rva>65536){oversized++;continue;}
    int size=checked((int)(end-rva));var body=raw.AsSpan(checked(0x100+(int)rva),size);scanned++;
    var old=Baseline.ClassInitSites(body,rva).Where(s=>s.Target==helper).ToArray();var current=Current.ClassInitSites(body,rva).Where(s=>s.Target==helper).ToArray();oldTotal+=old.Length;newTotal+=current.Length;
    var oldStarts=old.Select(s=>s.Start).ToHashSet();var newStarts=current.Select(s=>s.Start).ToHashSet();
    foreach(var site in current.Where(s=>!oldStarts.Contains(s.Start))){
        int index=checked((int)(site.Start-rva));var loads=new List<string>();
        for(int offset=index-4;offset>=Math.Max(0,index-16);offset-=4){uint w=BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(offset,4));if((w&0xffc0001f)==0xf9400000&&((w>>10)&0xfff)==0)break;if((w&0xffc00000)==0xb9400000&&(w&31)!=0)loads.Add($"0x{rva+(ulong)offset:X}");}
        if(loads.Count==0)throw new InvalidOperationException("New accepted site has no newly admitted scheduled Wn read");
        added.Add(new{fde_rva=$"0x{rva:X}",fde_bytes=size,start=$"0x{site.Start:X}",call=$"0x{site.Start+16:X}",skip=$"0x{site.Skip:X}",scheduled_32bit_read_addresses=loads});
    }
    foreach(var site in old.Where(s=>!newStarts.Contains(s.Start))){int index=checked((int)(site.Start-rva));uint flag=BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(index,4)),finished=BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(index+8,4));if((flag&31)!=0&&(finished&31)!=0)throw new InvalidOperationException("Accepted site removed without W0 class receiver clobber");removed.Add(new{fde_rva=$"0x{rva:X}",start=$"0x{site.Start:X}",flag_destination=flag&31,finished_destination=finished&31});}
}
var source=File.ReadAllBytes(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64AllocationPattern.cs"));
var report=new{status="PASS_FROZEN_V32_VS_V33_EXACT_FDE_STATIC_GUARD_CANDIDATE_SCAN",parsed_frame_records=parsed,unique_frame_starts=frames.Count,scanned_exact_frames=scanned,skipped_ambiguous_ranges=ambiguous,skipped_outside_text_or_alignment=outside,skipped_over_64k=oversized,known_helper="0xB2E720",v32_candidates=oldTotal,v33_candidates=newTotal,new_candidates=added.Count,removed_candidates=removed.Count,added,removed,
    v32_source_sha256=Hash(original),v32_namespaced_source_sha256=Hash(baseline),v33_source_sha256=Hash(source),original_native_sha256=Hash(raw),
    scope="Both actual matcher sources are compiled together into a disjoint BCL-only executable. Baseline is extracted byte-for-byte from frozen v32 patch effbf13 and hash checked; only its namespace changes for co-compilation. Scan uses exact bounded original FDE ranges and known initializer target. Counts measure static native instruction-window candidates only. They do not certify decoded CFG reachability, alternate-entry coverage, integration acceptance, typed class origin, emitted CIL/source, initializer semantics, runtime parity or whole-game completeness."};
File.WriteAllText(Guard("reports/class-guard-scheduling-scale-v33.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,scanned,oldTotal,newTotal,added=added.Count,removed=removed.Count}));
