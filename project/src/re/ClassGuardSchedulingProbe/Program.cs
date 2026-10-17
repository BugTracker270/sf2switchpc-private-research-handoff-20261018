using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Cpp2IL.Core.Utils;

if(args.Length is <1 or >2||args.Length==2&&args[1]!="--v35")throw new ArgumentException("Verified USB root and optional --v35 required");
string reportLabel=args.Length==2?"v35":"v33";
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return path;}
string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
const ulong start=0x1000,helper=0xB2E720;
int checks=0;void Check(bool value,string name){if(!value)throw new Exception(name);checks++;}
uint Call(ulong pc,ulong target)=>0x94000000u|((uint)((long)target-(long)pc)/4&0x03ffffffu);
byte[] Fixture(uint? scheduled=0xB9401675){
    var words=new List<uint>{0xF9400260}; // ldr x0,[x19]
    if(scheduled is uint word)words.Add(word);
    int flag=words.Count;
    words.AddRange([0x39448808,0x36000088,0xB940D408,0x35000048,Call(start+(ulong)(flag+4)*4,helper),0xD65F03C0]);
    var bytes=new byte[words.Count*4];for(int i=0;i<words.Count;i++)BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i*4,4),words[i]);return bytes;
}
var names=new List<string>();
void Expect(byte[] bytes,bool accepted,string name){var before=Hash(bytes);var sites=LegacyArm64AllocationPattern.ClassInitSites(bytes,start).Where(s=>s.Target==helper).ToArray();Check((sites.Length==1)==accepted,name);Check(Hash(bytes)==before,"Matcher mutated original instructions: "+name);names.Add(name);}
Expect(Fixture(),true,"scheduled unsigned-offset W21 read");
Expect(Fixture(null),true,"existing adjacent X0 class load");
Expect(Fixture(0xB9401661),true,"scheduled unsigned-offset W1 read");
Expect(Fixture(0xB940167F),true,"scheduled unsigned-offset WZR read");
Expect(Fixture(0xB9401660),false,"scheduled W0 overwrites X0 receiver");
Expect(Fixture(0xB8404E75),false,"scheduled pre-index W21 load writes back base");
Expect(Fixture(0xB8404675),false,"scheduled post-index W21 load writes back base");
Expect(Fixture(0xB9001675),false,"scheduled W21 store is outside witness");
Expect(Fixture(0x91002000),false,"scheduled ADD changes class receiver");
Expect(Fixture(0x94000001),false,"scheduled extra call is outside witness");
var badClass=Fixture();BinaryPrimitives.WriteUInt32LittleEndian(badClass,0xF9400660);Expect(badClass,false,"class slot load with nonzero addend");
var badFlag=Fixture();BinaryPrimitives.WriteUInt32LittleEndian(badFlag.AsSpan(8,4),0x39448408);Expect(badFlag,false,"wrong has-cctor offset");
var badFinish=Fixture();BinaryPrimitives.WriteUInt32LittleEndian(badFinish.AsSpan(16,4),0xB940D008);Expect(badFinish,false,"wrong cctor-finished offset");
var badJoin=Fixture();BinaryPrimitives.WriteUInt32LittleEndian(badJoin.AsSpan(12,4),0x360000A8);Expect(badJoin,false,"class guard branches disagree");
var otherHelper=Fixture();BinaryPrimitives.WriteUInt32LittleEndian(otherHelper.AsSpan(24,4),Call(start+24,helper+4));Expect(otherHelper,false,"different known-helper target excluded by caller identity gate");
var flagClobbersClass=Fixture();BinaryPrimitives.WriteUInt32LittleEndian(flagClobbersClass.AsSpan(8,4),0x39448800);BinaryPrimitives.WriteUInt32LittleEndian(flagClobbersClass.AsSpan(12,4),0x36000080);Expect(flagClobbersClass,false,"paired flag load/test W0 overwrites X0 class receiver");
var finishedClobbersClass=Fixture();BinaryPrimitives.WriteUInt32LittleEndian(finishedClobbersClass.AsSpan(16,4),0xB940D400);BinaryPrimitives.WriteUInt32LittleEndian(finishedClobbersClass.AsSpan(20,4),0x35000040);Expect(finishedClobbersClass,false,"paired finished load/test W0 overwrites X0 class receiver");
var raw=File.ReadAllBytes(Guard("analysis/nso/main-uncompressed.nso"));Check(Hash(raw)=="bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968","Original native binary differs");
var expected=new Dictionary<ulong,(string Name,int Size,int Native)>{{0xF0D390,("BinaryReaderNekki::ReadBoolean",148,1)},{0x4A83A0,("BundlesUtil::UnloadDependencies",384,2)},{0x4A8920,("BundlesUtil::GetAssetBundleSafe",256,3)}};
var acceptedStarts=new Dictionary<ulong,ulong[]>{{0xF0D390,[0xF0D3DC]},{0x4A83A0,[0x4A83EC,0x4A84D8]},{0x4A8920,[0x4A89D0]}};
var frameSizes=new Dictionary<ulong,int>();
foreach(var line in File.ReadLines(Guard("analysis/nso/unwind-inventory-v1/frames.jsonl"))){using var doc=JsonDocument.Parse(line);var row=doc.RootElement;ulong rva=row.GetProperty("rva").GetUInt64();if(expected.ContainsKey(rva)){Check(!frameSizes.ContainsKey(rva),"Ambiguous original FDE");frameSizes[rva]=checked((int)(row.GetProperty("end_rva").GetUInt64()-rva));}}
var native=new List<object>();
foreach(var (rva,description) in expected){
    Check(frameSizes.TryGetValue(rva,out var size)&&size==description.Size,"Original exact FDE differs");var body=raw.AsSpan(checked(0x100+(int)rva),size).ToArray();var sites=LegacyArm64AllocationPattern.ClassInitSites(body,rva).Where(s=>s.Target==helper).ToArray();
    var calls=new HashSet<ulong>();for(int i=0;i<body.Length;i+=4){uint word=BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(i,4));if((word&0xfc000000)!=0x94000000)continue;long delta=((int)(word<<6)>>6)*4L;ulong target=unchecked((ulong)((long)rva+i+delta));if(target==helper)calls.Add(rva+(ulong)i);}
    Check(calls.Count==description.Native,"Original native initializer count differs");
    Check(sites.Select(s=>s.Start).SequenceEqual(acceptedStarts[rva]),"Original accepted guard set changed");
    foreach(var site in sites){Check(calls.Contains(site.Start+16),"Matched guard is not the exact known native call");Check(site.Start>=rva&&site.Skip<=rva+(ulong)size,"Matched guard escaped original FDE");}
    if(rva==0xF0D390){Check(sites is [{Start:0xF0D3DC,Skip:0xF0D3F0}],"Original ReadBoolean scheduled-load guard did not match exactly");Check(BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(0x48,4))==0xB9401675,"Original W21 load differs");Check(0xF0D3D8<sites[0].Start,"Scheduled input read would be in replaced guard");}
    native.Add(new{method=description.Name,rva=$"0x{rva:X}",exact_fde_bytes=size,native_class_init_calls=calls.Count,recognized_guards=sites.Length,remaining_unmatched_calls=calls.Count-sites.Length,body_sha256=Hash(body),guards=sites.Select(s=>new{start=$"0x{s.Start:X}",skip=$"0x{s.Skip:X}",target=$"0x{s.Target:X}"}).ToArray()});
}
var source=File.ReadAllBytes(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64AllocationPattern.cs"));
var report=new{status="PASS_BOUNDED_32BIT_CLASS_GUARD_SCHEDULING_RECOGNITION",checks,fixtures=names,source_sha256=Hash(source),native,
    scope="BCL-only fixture compiles the actual matcher source into a disjoint executable, without building shared Core. It verifies exact original FDE/native call correlation, the newly accepted independent unsigned-offset Wn scheduling, unchanged input bytes and strict malformed receiver/writeback/effect/layout/target rejection. Original ReadBoolean scheduled W21 load precedes and remains outside the replaced guard. No emitted CIL, class-initializer execution, source compilation, whole-caller behavior or whole-game claim is made here."};
File.WriteAllText(Guard($"reports/class-guard-scheduling-{reportLabel}.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,checks,native}));
