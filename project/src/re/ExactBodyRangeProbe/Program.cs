using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;

if(args.Length is <1 or >2||args.Length==2&&!System.Text.RegularExpressions.Regex.IsMatch(args[1],"^[a-z0-9-]+$"))throw new ArgumentException("Verified USB root and optional report label required");
string reportLabel=args.Length==2?args[1]:"v32";
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string p=Path.GetFullPath(Path.Combine(root,relative));
    if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");
    for(DirectoryInfo? d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)
        if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point forbidden");
    return p;
}
string Hash(string p)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p))).ToLowerInvariant();
string binary=Guard("unpacked/effective/exefs/main"),metadata=Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if(Hash(binary)!="94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"||Hash(metadata)!="f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85")throw new IOException("Original input hash differs");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary,metadata,new UnityVersion(2018,1,9,UnityVersionType.Final,1));
var app=Cpp2IlApi.CurrentAppContext!;
var hasOpen=typeof(Cpp2IlApi).Assembly.GetType("Cpp2IL.Core.Utils.GenericInstantiation",true)!.GetMethod("HasAnyGenericParameters",BindingFlags.Public|BindingFlags.Static)!;
bool HasOpen(TypeAnalysisContext t)=>(bool)hasOpen.Invoke(null,[t])!;
var types=app.Assemblies.SelectMany(a=>a.Types).ToArray();
var getter=types.Single(t=>t.FullName=="CodeStage.AntiCheat.Detectors.ObscuredCheatingDetector").Methods.Single(m=>m.Name=="get_Instance");
var adjustor=types.Single(t=>t.FullName=="CodeStage.AntiCheat.ObscuredTypes.ObscuredInt").Methods.Single(m=>m.Name=="InternalDecrypt");
var tests=new List<object>();
void Check(string name,bool ok){tests.Add(new{name,status=ok?"PASS":"FAIL"});}
int mappingCount=LegacyArm64ValueThisThunks.AcceptedMappings(app).Count;
ulong getterPointer=getter.UnderlyingPointer;
Check("registered static getter exact84byte FDE",getterPointer==0x78C270&&LegacyArm64ValueThisThunks.TryGetExactBodyRange(getter,out int getterSize)&&getterSize==84);
Check("range API does not select static getter replacement",!LegacyArm64ValueThisThunks.TryGetBody(getter,out _,out _)&&LegacyArm64ValueThisThunks.AnalysisAddress(getter)==getterPointer);
Check("address-only overload agrees without selecting identity",LegacyArm64ValueThisThunks.TryGetExactBodyRange(app,getterPointer,out int addressExtent)&&addressExtent==84);
Check("unregistered native constructor exact16byte FDE",LegacyArm64ValueThisThunks.TryGetExactBodyRange(app,0x11DD130,out int constructorExtent)&&constructorExtent==16);
Check("reviewed generic getter exact36byte FDE",LegacyArm64ValueThisThunks.TryGetExactBodyRange(app,0x1585F60,out int enumeratorExtent)&&enumeratorExtent==36);
Check("interior address is not an FDE start",!LegacyArm64ValueThisThunks.TryGetExactBodyRange(app,getterPointer+4,out int interiorExtent)&&interiorExtent==0);
Check("range API uses original adjustor8bytes",LegacyArm64ValueThisThunks.TryGetExactBodyRange(adjustor,out int wrapper)&&wrapper==8);
Check("selected adjustor analysis remains520bytes",LegacyArm64ValueThisThunks.TryGetBody(adjustor,out ulong target,out int selected)&&target==0x7A8F20&&selected==520);
var results=new bool[256];Parallel.For(0,results.Length,i=>results[i]=LegacyArm64ValueThisThunks.TryGetExactBodyRange(getter,out int n)&&n==84);
Check("parallel lazy range cache queries",results.All(x=>x));
var zero=types.SelectMany(t=>t.Methods).First(m=>m.UnderlyingPointer==0);
Check("unregistered zero pointer has no range",!LegacyArm64ValueThisThunks.TryGetExactBodyRange(zero,out int absent)&&absent==0);
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA",null);
Check("opt-in disabled refuses exact bounds",!LegacyArm64ValueThisThunks.TryGetExactBodyRange(getter,out int disabled)&&disabled==0);
Check("opt-in disabled refuses address-only bounds",!LegacyArm64ValueThisThunks.TryGetExactBodyRange(app,0x11DD130,out int disabledNative)&&disabledNative==0);
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");
Check("range queries preserve pointers and alias selection",getter.UnderlyingPointer==getterPointer&&mappingCount==LegacyArm64ValueThisThunks.AcceptedMappings(app).Count);

ulong methodSlot=app.Binary.ReadPointerAtVirtualAddress(0x39D61A0);
var concrete=app.ResolveContextForMethod(app.LibCpp2IlContext.GetMethodGlobalByAddress(methodSlot))??throw new IOException("Concrete method metadata unresolved");
var returned=(GenericInstanceTypeAnalysisContext)concrete.ReturnType;
var definition=returned.GenericType;
var fields=definition.Fields.Where(f=>!f.IsStatic&&(f.Attributes&FieldAttributes.Literal)==0).Select(f=>new ConcreteGenericFieldAnalysisContext(f,returned)).ToArray();
long end=0,alignment=1;var fieldEvidence=new List<object>();bool supported=true;
foreach(var field in fields)
{
    var type=field.FieldType;
    int size=HasOpen(type)||type is PointerTypeAnalysisContext or ByRefTypeAnalysisContext?0:!type.IsValueType?8:type.FullName=="System.Int32"?4:0;
    if(size==0){supported=false;break;}
    end=(end+size-1)&-size;alignment=Math.Max(alignment,size);
    fieldEvidence.Add(new{field.Name,raw_metadata_offset=field.Offset,closed_type=type.FullName,reference_type=!type.IsValueType,inferred_offset=end,inferred_size=size});end+=size;
}
long inferred=supported?(end+alignment-1)&-alignment:0;
Check("closed Model return remains definition-null size0",concrete.DeclaringType?.FullName.Contains("Model.Model")==true&&returned.Definition==null&&!HasOpen(returned)&&TypeSizes.UnboxedSize(returned,8)==0);
Check("closed substituted fourfield evidence computes24",supported&&fields.Length==4&&inferred==24&&definition.Definition!=null&&definition.Definition.PackingSize==0&&(definition.Attributes&TypeAttributes.LayoutMask)==TypeAttributes.SequentialLayout);
var report=new{status=tests.All(t=>JsonSerializer.Serialize(t).Contains("PASS"))?"PASS_ORIGINAL_POINTER_FDE_RANGE_API_AND_CLOSED_ENUMERATOR_EVIDENCE":"PROBE_EXPECTATION_FAILED",checks=tests.Count,tests,
    getter=new{rva=$"0x{getterPointer:X}",exact_fde_bytes=84,range_does_not_select_body=true},
    closed_enumerator=new{methodinfo_slot=$"0x{methodSlot:X}",concrete_method=concrete.FullName,returned_type=returned.FullName,definition_is_null=returned.Definition==null,
        definition_type=definition.FullName,definition_boxed_size=definition.Definition?.RawSizes.instance_size,definition.Attributes,fields=fieldEvidence,inferred_unboxed_size=inferred,
        native_size_witness="reports/enumerator-native-return-v31.json",classification_changed=false},
    loaded_core_sha256=Hash(typeof(Cpp2IlApi).Assembly.Location),
    scope="Bounds-only API at original registered native pointer; no identity or alias selection. Fourfield sequential ref/int/int/ref computation is corroborative scoped evidence, not a general generic layout classifier. Open, value-type, packing, explicit and unresolved substitutions require independent proof. No game method executed."};
File.WriteAllText(Guard($"reports/exact-body-range-and-closed-enumerator-{reportLabel}.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+Environment.NewLine);
Console.WriteLine(JsonSerializer.Serialize(report));
return tests.All(t=>JsonSerializer.Serialize(t).Contains("PASS"))?0:1;
