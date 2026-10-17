using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Cpp2IL.Core.Utils;

if(args.Length is <1 or >2||args.Length==2&&!System.Text.RegularExpressions.Regex.IsMatch(args[1],"^[a-z0-9-]+$")) throw new ArgumentException("Verified USB workspace root and optional report label required");
string reportLabel=args.Length==2?args[1]:"v31";
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string p=Path.GetFullPath(Path.Combine(root,relative));
    if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for(DirectoryInfo? d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)
        if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point forbidden");
    return p;
}
var image=File.ReadAllBytes(Guard("analysis/nso/main-uncompressed.nso"));
if(Convert.ToHexString(SHA256.HashData(image)).ToLowerInvariant()!="bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968")throw new IOException("Original binary hash differs");
uint U32(int i)=>BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(i,4));
if(U32(0)!=0x304f534e)throw new IOException("NSO required");
const ulong start=0x7A8F20;
int raw=checked((int)(U32(0x10)+start-U32(0x14)));
byte[] body=image.AsSpan(raw,520).ToArray();
string hash=Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
ulong writable=U32(0x34),end=writable+U32(0x38)+U32(0x3c);
LegacyArm64CfgInitializationPattern.Result Match(byte[] data,ulong metadata=0xB12650,ulong klass=0xB2E720,ulong? ws=null,ulong? we=null)
    =>LegacyArm64CfgInitializationPattern.Match(data,start,metadata,klass,ws??writable,we??end);
byte[] Change(ulong rva,uint word){var b=(byte[])body.Clone();BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(checked((int)(rva-start)),4),word);return b;}
byte[] ChangeTwo(ulong a,uint av,ulong b,uint bv){var data=Change(a,av);BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(checked((int)(b-start)),4),bv);return data;}
uint Word(ulong rva)=>BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(checked((int)(rva-start)),4));
var tests=new List<object>();
void Check(string name,bool ok){tests.Add(new{name,status=ok?"PASS":"FAIL"});}
var result=Match(body);
Console.WriteLine(JsonSerializer.Serialize(new{hash,metadata=result.MetadataGuards,classes=result.ClassGuards}));
ulong[] loads=[0x7A8F3C,0x7A8FA0,0x7A8FD8,0x7A9048,0x7A90D0,0x7A9054,0x7A9118];
Check("seven exact metadata sites",result.MetadataGuards.Select(g=>g.Load).Order().SequenceEqual(loads.Order()));
Check("one exact cold class site",result.ClassGuards.Count(g=>g.Start==0x7A9038&&g.Skip==0x7A9048&&g.ClassLoad==0x7A9030&&g.Target==0xB2E720&&g.ClassRegister==0)==1);
Check("all five exact inline and cold class sites",result.ClassGuards.Select(g=>g.Start).Order().SequenceEqual(new ulong[]{0x7A8F7C,0x7A8FC4,0x7A8FFC,0x7A9038,0x7A90F8}));
Check("metadata identity mismatch rejected",Match(body,metadata:0xB12654).MetadataGuards.Count==0);
Check("class identity mismatch rejected",Match(body,klass:0xB2E724).ClassGuards.Count==0);
Check("read-only flags rejected",Match(body,ws:0,we:1).MetadataGuards.Count==0);
Check("unknown base assignment rejected",Match(Change(0x7A8F38,0xAA0003F5)).MetadataGuards.Count==0);
Check("base clobber on one predecessor rejects joined cold sites",!Match(Change(0x7A8F68,0xAA0003F5)).MetadataGuards.Any(g=>g.Load>=0x7A9028));
Check("wrong metadata argument register rejected",!Match(Change(0x7A90E0,Word(0x7A90E0)|1)).MetadataGuards.Any(g=>g.Flag==0x3A36682));
Check("initializer extra effect rejected",!Match(Change(0x7A90E8,0x110006f7)).MetadataGuards.Any(g=>g.Flag==0x3A36682));
Check("semantic EOR remains separate",result.MetadataGuards.Any(g=>g.Load==0x7A9054&&g.Branch==0x7A905C&&g.Skip==0x7A9078)&&Word(0x7A9058)==0x4A1402F4);
Check("semantic EOR flag use rejected",!Match(Change(0x7A9058,0x4A140114)).MetadataGuards.Any(g=>g.Load==0x7A9054));
int jumpToEor=checked((int)((0x7A9058L-0x7A8F6CL)/4));
Check("external entry into scheduled arithmetic rejects guard",!Match(Change(0x7A8F6C,0x14000000u|((uint)jumpToEor&0x3ffffff))).MetadataGuards.Any(g=>g.Load==0x7A9054));
Check("semantic cold continuation branch mismatch rejected",!Match(Change(0x7A90F0,Word(0x7A90F0)^1)).MetadataGuards.Any(g=>g.Flag==0x3A36682));
Check("class header mismatch rejected",!Match(Change(0x7A9038,Word(0x7A9038)+0x400)).ClassGuards.Any(g=>g.Start==0x7A9038));
Check("class flag must not clobber X0 receiver",!Match(ChangeTwo(0x7A9038,Word(0x7A9038)&~31u,0x7A903C,Word(0x7A903C)&~31u)).ClassGuards.Any(g=>g.Start==0x7A9038));
Check("class finished load must not clobber X0 receiver",!Match(ChangeTwo(0x7A9040,Word(0x7A9040)&~31u,0x7A9044,Word(0x7A9044)&~31u)).ClassGuards.Any(g=>g.Start==0x7A9038));
Check("class load receiver mismatch rejected",!Match(Change(0x7A9030,Word(0x7A9030)|1)).ClassGuards.Any(g=>g.Start==0x7A9038));
Check("class cold helper mismatch rejected",!Match(Change(0x7A90CC,Word(0x7A90CC)+1)).ClassGuards.Any(g=>g.Start==0x7A9038));
Check("class reload unrelated effect rejected",!Match(Change(0x7A8F90,0xB9000274)).ClassGuards.Any(g=>g.Start==0x7A8F7C));
Check("flag semantic use after skip rejected",!Match(Change(0x7A9078,0x4A0802f4)).MetadataGuards.Any(g=>g.Flag==0x3A36614));
Check("MOVK preserves flag bits and rejects suppression",!Match(Change(0x7A9078,0x72800008)).MetadataGuards.Any(g=>g.Flag==0x3A36614));
Check("external tail call cannot prove flag death",!Match(Change(0x7A9078,0x14010000)).MetadataGuards.Any(g=>g.Flag==0x3A36614));
var effect=typeof(LegacyArm64CfgInitializationPattern).GetNestedType("Matcher",System.Reflection.BindingFlags.NonPublic)!.GetMethod("Effects",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
object?[] returnEffect=[0xD65F03C0u,0u,0u,false];effect.Invoke(null,returnEffect);
Check("RET conservatively reads integer return registers",((uint)returnEffect[1]!&3)==3);
Check("truncated body cannot recover final scheduled guard",!Match(body[..512]).MetadataGuards.Any(g=>g.Load==0x7A9118));
Check("misaligned body rejected",Match(body[..519]).MetadataGuards.Count==0);
var report=new{status=tests.All(t=>JsonSerializer.Serialize(t).Contains("PASS"))?"PASS_SCOPED_CFG_INITIALIZATION_RECOGNITION":"FAIL_SCOPED_CFG_INITIALIZATION_RECOGNITION",native_start=$"0x{start:X}",native_bytes=body.Length,native_sha256=hash,checks=tests.Count,tests,metadata_guards=result.MetadataGuards,class_guards=result.ClassGuards,scope="Exact 520-byte original FDE body matcher only; no recovered CLR execution or class-constructor equivalence claim."};
File.WriteAllText(Guard($"reports/cfg-initialization-recognition-{reportLabel}.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+Environment.NewLine);
Console.WriteLine(JsonSerializer.Serialize(report));
return tests.All(t=>JsonSerializer.Serialize(t).Contains("PASS"))?0:1;
