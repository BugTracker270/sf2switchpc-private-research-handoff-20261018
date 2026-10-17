using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;

if(args.Length!=1)throw new ArgumentException("Verified USB root required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return path;}
string Hash(string path){using var file=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant();}
string binary=Guard("unpacked/effective/exefs/main"),metadata=Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if(Hash(binary)!="94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"||Hash(metadata)!="f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85")throw new IOException("Input differs");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));Cpp2IlApi.InitializeLibCpp2Il(binary,metadata,new UnityVersion(2018,1,9,UnityVersionType.Final,1));
var app=Cpp2IlApi.CurrentAppContext!;var keys=app.GetOrCreateKeyFunctionAddresses();
var owner=app.Assemblies.SelectMany(a=>a.Types).Single(t=>t.FullName=="CodeStage.AntiCheat.Detectors.ObscuredCheatingDetector");
var getter=owner.Properties.Single(p=>p.Name=="Instance").Getter!;
var field=owner.Fields.Single(f=>f.Name=="<Instance>k__BackingField");
int checks=0;var rejected=new List<string>();void Check(bool value,string name){if(!value)throw new Exception(name);checks++;}
Check(getter.UnderlyingPointer==0x78C270,"Getter pointer differs");
Check(field.IsStatic&&field.Visibility==FieldAttributes.Private&&field.Offset==8,"Original private static field identity differs");
Check(!owner.Methods.Any(m=>m.Name==".cctor"),"Owner has a managed initializer");
Check(LegacyArm64ValueThisThunks.TryGetExactBodyRange(getter,out var size)&&size==84,"Exact registered-address FDE differs");
Check(LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Original getter proof failed");
Check(ReferenceEquals(LegacyArm64LeafAccessors.FindStaticGetter(field),getter),"Existing getter not selected");
var raw=app.Binary.GetRawBinaryContent();var start=(int)app.Binary.MapVirtualAddressToRaw(getter.UnderlyingPointer);var body=raw.Slice(start,size).ToArray();
var writable=BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(0x34,4));var writableEnd=(ulong)writable+BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(0x38,4))+BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(0x3C,4));
bool Decode(byte[] bytes,ulong initializer,out ulong got)=>LegacyArm64LeafAccessors.TryDecodeStaticGetter(bytes,getter.UnderlyingPointer,initializer,0xF9400000,8,field.Offset,writable,writableEnd,out got);
Check(keys.il2cpp_codegen_initialize_method==0xB12650,"Metadata assurance helper differs");
Check(Decode(body,keys.il2cpp_codegen_initialize_method,out var got),"Metadata assurance/field decode failed");
var slot=app.Binary.ReadPointerAtVirtualAddress(got);
Check(app.LibCpp2IlContext.GetTypeGlobalByAddress(slot) is {} type&&ReferenceEquals(app.ResolveIl2CppType(type),owner),"GOT type usage does not identify actual owner");
foreach(var (name,index,replacement) in new (string,int,uint)[]{("extra effect",11,0xF9000100),("missing metadata guard",6,0xD503201F),("wrong static-field offset",18,0xF9400900),("wrong class-storage offset",17,0xF9405908),("unbalanced register restore",19,0xF84107F3),("missing return",20,0xD503201F)}){
    var changed=(byte[])body.Clone();BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(index*4,4),replacement);Check(!Decode(changed,keys.il2cpp_codegen_initialize_method,out _),name+" accepted");rejected.Add(name);
}
Check(!Decode(body,keys.il2cpp_codegen_initialize_method+4,out _),"Wrong assurance helper accepted");
var oldOffset=field.OverrideOffset;try{foreach(var offset in new[]{0,7,16}){field.Offset=offset;Check(!LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Wrong metadata field offset accepted");}}finally{field.OverrideOffset=oldOffset;}
var oldAttributes=field.OverrideAttributes;try{field.Attributes|=FieldAttributes.Literal;Check(!LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Literal accepted");field.Attributes=(oldAttributes??field.DefaultAttributes)&~FieldAttributes.Static;Check(!LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Instance field accepted");}finally{field.OverrideAttributes=oldAttributes;}
var oldMethodAttributes=getter.OverrideAttributes;try{getter.Attributes=(getter.Attributes&~MethodAttributes.MemberAccessMask)|MethodAttributes.Private;Check(!LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Private getter accepted");getter.Attributes=(oldMethodAttributes??getter.DefaultAttributes)|MethodAttributes.Virtual;Check(!LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Virtual getter accepted");getter.Attributes=(oldMethodAttributes??getter.DefaultAttributes)&~MethodAttributes.Static;Check(!LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Instance getter accepted");}finally{getter.OverrideAttributes=oldMethodAttributes;}
var injectedCtor=new InjectedMethodAnalysisContext(owner,".cctor",app.SystemTypes.SystemVoidType,MethodAttributes.Private|MethodAttributes.Static,[]);owner.Methods.Add(injectedCtor);try{Check(!LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Initializer owner accepted");}finally{owner.Methods.Remove(injectedCtor);}
var aliases=app.MethodsByAddress[getter.UnderlyingPointer];aliases.Add(getter);try{Check(!LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Ambiguous native aliases accepted");}finally{aliases.RemoveAt(aliases.Count-1);}
Check(!LegacyArm64LeafAccessors.IsExactStaticGetter(owner.Fields.Single(f=>f.Name=="instancesInScene"),getter),"Different static field accepted");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA",null);Check(LegacyArm64LeafAccessors.FindStaticGetter(field)==null&&!LegacyArm64LeafAccessors.IsExactStaticGetter(field,getter),"Opt-in disabled gate failed");Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");
Check(field.IsStatic&&field.Visibility==FieldAttributes.Private&&field.Offset==8,"Metadata test mutations were not restored");
var report=new{status="PASS_STATIC_GETTER_NATIVE_METADATA_AND_NEGATIVE_GUARDS",checks,owner=owner.FullName,field=field.Name,field_offset=field.Offset,field_visibility=field.Visibility.ToString(),field_type=field.FieldType.FullName,owner_cctor=false,
    getter=getter.FullName,getter_rva="0x78C270",getter_fde_bytes=size,getter_native_sha256=Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant(),metadata_initializer="0xB12650",type_got=$"0x{got:X}",type_metadata_slot=$"0x{slot:X}",static_storage_offset=184,rejected_patterns=rejected,
    input_binary_sha256=Hash(binary),input_metadata_sha256=Hash(metadata),core_sha256=Hash(typeof(LegacyArm64LeafAccessors).Assembly.Location),original_files_modified=false,
    scope="Exact registered getter FDE, same-owner type-global identity, public static property metadata and full reachable instruction shape are proven. Only method-metadata assurance precedes the private static field read; owners with any .cctor are rejected. The original field remains private. This selection probe does not execute the native getter, recovered CIL or active detector/callback paths."};
File.WriteAllText(Guard("reports/static-leaf-getter-selection-v31b.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,checks}));
