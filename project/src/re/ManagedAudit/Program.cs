using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;

if(args.Length is <3 or >4||(args.Length==4&&args[3]!="--attribute-contracts"))throw new ArgumentException("USB root, assembly directory, output directory, optional --attribute-contracts required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string source=Guard(args[1]),output=Guard(args[2]);
Directory.CreateDirectory(output);
Dictionary<ushort,OpCode> opcodes=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static)
    .Where(f=>f.FieldType==typeof(OpCode)).Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
List<object> assemblies=[];
foreach(string file in Directory.EnumerateFiles(source,"*.dll").Order()) {
    using FileStream stream=File.OpenRead(file);using PEReader pe=new(stream);MetadataReader metadata=pe.GetMetadataReader();
    if(args.Length==4) {
        var members=new List<object>();
        foreach(var handle in metadata.CustomAttributes) {
            var attribute=metadata.GetCustomAttribute(handle);
            if(MemberName(metadata,attribute.Constructor)!="System.Reflection.DefaultMemberAttribute::.ctor")continue;
            if(attribute.Parent.Kind!=HandleKind.TypeDefinition)throw new InvalidDataException("Unexpected DefaultMember owner kind");
            var blob=metadata.GetBlobReader(attribute.Value);
            if(blob.ReadUInt16()!=1)throw new InvalidDataException("Invalid attribute prolog");
            string? value=blob.ReadSerializedString();
            if(value==null||blob.ReadUInt16()!=0||blob.RemainingBytes!=0)throw new InvalidDataException("Unexpected DefaultMember attribute encoding");
            var owner=metadata.GetTypeDefinition((TypeDefinitionHandle)attribute.Parent);
            int matchingProperties=owner.GetProperties().Count(p=>metadata.GetString(metadata.GetPropertyDefinition(p).Name)==value);
            if(matchingProperties==0)throw new InvalidDataException("DefaultMember value has no metadata property witness");
            members.Add(new{owner=TypeName(metadata,attribute.Parent),value,matching_properties=matchingProperties});
        }
        assemblies.Add(new{file=Path.GetFileName(file),sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))).ToLowerInvariant(),default_member_count=members.Count,default_members=members});
        continue;
    }
    int methods=0,bodies=0,simple=0,diagnostics=0,helpers=0,failures=0,throws=0,stackRejections=0;
    var attributeConstructors=new Dictionary<string,int>();
    foreach(var attributeHandle in metadata.CustomAttributes) {
        var attribute=metadata.GetCustomAttribute(attributeHandle);
        string constructor=MemberName(metadata,attribute.Constructor);
        attributeConstructors[constructor]=attributeConstructors.GetValueOrDefault(constructor)+1;
    }
    using StreamWriter writer=new(Path.Combine(output,Path.GetFileNameWithoutExtension(file)+".jsonl"));
    foreach(TypeDefinitionHandle typeHandle in metadata.TypeDefinitions) {
        TypeDefinition type=metadata.GetTypeDefinition(typeHandle);string typeName=TypeName(metadata,typeHandle);
        foreach(MethodDefinitionHandle methodHandle in type.GetMethods()) {
            methods++; MethodDefinition method=metadata.GetMethodDefinition(methodHandle); string methodName=metadata.GetString(method.Name);
            if(method.RelativeVirtualAddress==0)continue;
            bodies++; byte[] il=pe.GetMethodBody(method.RelativeVirtualAddress).GetILBytes()??[];
            List<string> operations=[],calls=[],messages=[];string? error=null;int position=0;
            try {
                while(position<il.Length) {
                    ushort code=il[position++];if(code==0xfe)code=(ushort)(0xfe00|il[position++]);
                    if(!opcodes.TryGetValue(code,out OpCode op))throw new InvalidDataException("Unknown IL opcode");
                    operations.Add(op.Name!);int token=0;
                    switch(op.OperandType) {
                        case OperandType.InlineNone:break;
                        case OperandType.ShortInlineI:case OperandType.ShortInlineVar:case OperandType.ShortInlineBrTarget:position++;break;
                        case OperandType.InlineVar:position+=2;break;
                        case OperandType.InlineI8:case OperandType.InlineR:position+=8;break;
                        case OperandType.InlineSwitch:int count=BitConverter.ToInt32(il,position);position+=checked(4+count*4);break;
                        default:token=BitConverter.ToInt32(il,position);position+=4;break;
                    }
                    if(position>il.Length)throw new InvalidDataException("Truncated IL operand");
                    if(op.OperandType==OperandType.InlineMethod)calls.Add(MemberName(metadata,MetadataTokens.EntityHandle(token)));
                    if(op.OperandType==OperandType.InlineString) {
                        string value=metadata.GetUserString(MetadataTokens.UserStringHandle(token&0xffffff));
                        if(value.Contains("not yet implemented",StringComparison.OrdinalIgnoreCase)||
                           value.Contains("Jump target not found",StringComparison.OrdinalIgnoreCase)||
                           value.Contains("Cpp2IL",StringComparison.OrdinalIgnoreCase)||
                           value.Contains("Unmanaged memory load",StringComparison.OrdinalIgnoreCase)||
                           value.Contains("Method not found",StringComparison.OrdinalIgnoreCase)||
                           value.Contains("Unhandled instruction",StringComparison.OrdinalIgnoreCase)||
                           value.Contains("not implemented",StringComparison.OrdinalIgnoreCase)||
                           value.Contains("StackImbalanceException",StringComparison.Ordinal)||
                           value.Contains("InvalidCilInstructionException",StringComparison.Ordinal))messages.Add(value);
                    }
                }
            } catch(Exception ex){error=ex.GetType().Name+": "+ex.Message;failures++;}
            bool small=operations.Count<=3;
            bool helper=calls.Any(c=>c.Contains("Cpp2ILInjected",StringComparison.OrdinalIgnoreCase)||c.Contains("Unimplemented",StringComparison.OrdinalIgnoreCase));
            bool stackRejected=messages.Any(m=>m.Contains("StackImbalanceException",StringComparison.Ordinal)||m.Contains("InvalidCilInstructionException",StringComparison.Ordinal));
            if(stackRejected)stackRejections++;
            if(small)simple++;if(messages.Count>0)diagnostics++;if(helper)helpers++;if(operations.Contains("throw"))throws++;
            writer.WriteLine(JsonSerializer.Serialize(new {assembly=Path.GetFileName(file),type=typeName,name=methodName,
                token=$"0x{MetadataTokens.GetToken(methodHandle):X8}",body_bytes=il.Length,
                il_sha256=Convert.ToHexString(SHA256.HashData(il)).ToLowerInvariant(),opcodes=operations,
                call_targets=calls,diagnostic_messages=messages,small_body=small,has_recovery_helper=helper,stack_rejection_diagnostic=stackRejected,error,
                status=error!=null?"MALFORMED_IL":messages.Count>0||helper?"RECOVERY_LIMITATION_PRESENT":"SYNTACTIC_ONLY_NOT_SEMANTICALLY_VERIFIED"}));
        }
    }
    assemblies.Add(new {file=Path.GetFileName(file),methods,with_bodies=bodies,minimal_or_simple_bodies=simple,
        custom_attribute_count=metadata.CustomAttributes.Count,custom_attribute_constructor_counts=attributeConstructors,
        methods_with_diagnostic_strings=diagnostics,methods_with_recovery_helper_calls=helpers,methods_with_throw=throws,methods_with_stack_rejection_diagnostics=stackRejections,malformed_il=failures});
}
File.WriteAllText(Path.Combine(output,"summary.json"),JsonSerializer.Serialize(new {source_directory=source,assemblies,
    warning="Syntactic IL audit only. Recovery helpers/diagnostics invalidate blanket recovery success; simple bodies may be legitimate or stubs. No semantic parity is implied."},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine(JsonSerializer.Serialize(assemblies,new JsonSerializerOptions{WriteIndented=true}));

string Guard(string path) {
    string full=Path.GetFullPath(path);
    if(!full.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Output/input outside USB workspace");
    for(DirectoryInfo? cursor=new(Path.GetDirectoryName(full)!);cursor!=null;cursor=cursor.Parent)
        if(cursor.Exists && (cursor.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point forbidden");
    return full;
}

static string TypeName(MetadataReader r,EntityHandle h) => h.Kind switch {
    HandleKind.TypeDefinition=>Defined(r,(TypeDefinitionHandle)h),
    HandleKind.TypeReference=>Referenced(r,(TypeReferenceHandle)h),
    HandleKind.TypeSpecification=>"<TypeSpecification>",_=>h.Kind.ToString()};
static string Defined(MetadataReader r,TypeDefinitionHandle h) {
    var t=r.GetTypeDefinition(h);string n=r.GetString(t.Name),ns=r.GetString(t.Namespace);
    return !t.GetDeclaringType().IsNil?Defined(r,t.GetDeclaringType())+"+"+n:ns.Length>0?ns+"."+n:n;
}
static string Referenced(MetadataReader r,TypeReferenceHandle h) {
    var t=r.GetTypeReference(h);string n=r.GetString(t.Name),ns=r.GetString(t.Namespace);return ns.Length>0?ns+"."+n:n;
}
static string MemberName(MetadataReader r,EntityHandle h) {
    if(h.Kind==HandleKind.MethodSpecification)return MemberName(r,r.GetMethodSpecification((MethodSpecificationHandle)h).Method);
    if(h.Kind==HandleKind.MethodDefinition){var m=r.GetMethodDefinition((MethodDefinitionHandle)h);return TypeName(r,m.GetDeclaringType())+"::"+r.GetString(m.Name);}
    if(h.Kind==HandleKind.MemberReference){var m=r.GetMemberReference((MemberReferenceHandle)h);return TypeName(r,m.Parent)+"::"+r.GetString(m.Name);}
    return h.Kind.ToString();
}
