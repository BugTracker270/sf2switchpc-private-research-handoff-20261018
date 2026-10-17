using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if(args.Length!=2 || !Regex.IsMatch(args[1],"^[a-z0-9-]+$")) throw new ArgumentException("USB root and run required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),run=args[1];
string Guard(string relative) {
    string path=Path.GetFullPath(Path.Combine(root,relative));
    if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for(DirectoryInfo? dir=new(Path.GetDirectoryName(path)!);dir!=null;dir=dir.Parent)
        if(dir.Exists&&(dir.Attributes&FileAttributes.ReparsePoint)!=0) throw new IOException("Reparse point");
    return path;
}
string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
var ops=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static).Where(f=>f.FieldType==typeof(OpCode)).Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
string folder=Guard($"analysis/il2cpp/cpp2il-recovery-{run}");
AssemblyLoadContext.Default.Resolving+=(context,name)=>File.Exists(Path.Combine(folder,name.Name+".dll"))?context.LoadFromAssemblyPath(Path.Combine(folder,name.Name+".dll")):null;
var summary=new List<object>(); var details=new List<object>();
foreach(var pair in new[]{("Assembly-CSharp","Nekki.SF2.Core.Fights.Fight"),("Assembly-CSharp-firstpass","SevenZip.Compression.RangeCoder.BitTreeDecoder"),("Assembly-CSharp-firstpass","SevenZip.Compression.RangeCoder.BitTreeEncoder"),("Assembly-CSharp-firstpass","CodeStage.AntiCheat.ObscuredTypes.ObscuredDecimal"),("Assembly-CSharp-firstpass","nn.hid.GestureState")}) {
    var path=Path.Combine(folder,pair.Item1+".dll"); var asm=Assembly.LoadFrom(path);var type=asm.GetType(pair.Item2,true)!;
    foreach(var method in type.GetMethods(BindingFlags.DeclaredOnly|BindingFlags.Instance|BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic)) {
        if(pair.Item2=="Nekki.SF2.Core.Fights.Fight"&&method.Name!="SetStage")continue;
        var body=method.GetMethodBody();if(body==null)continue;var bytes=body.GetILAsByteArray()!;
        var rows=new List<(int offset,OpCode op,int operand,int end)>();
        for(int at=0;at<bytes.Length;) {
            int start=at;ushort code=bytes[at++];if(code==0xfe)code=(ushort)(0xfe00|bytes[at++]);var op=ops[code];int operand=at;
            at+=op.OperandType switch {OperandType.InlineNone=>0,OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget=>1,OperandType.InlineVar=>2,OperandType.InlineI8 or OperandType.InlineR=>8,OperandType.InlineSwitch=>4+4*BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at,4)),_=>4};
            rows.Add((start,op,operand,at));
        }
        int Index((int offset,OpCode op,int operand,int end) row)=>row.op.OperandType==OperandType.InlineNone?int.Parse(row.op.Name![^1..]):row.op.OperandType==OperandType.ShortInlineVar?bytes[row.operand]:BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(row.operand,2));
        string Operand((int offset,OpCode op,int operand,int end) row) {
            if(row.op.Name!.StartsWith("ldloc")||row.op.Name.StartsWith("stloc")||row.op.Name.StartsWith("ldarg"))return Index(row).ToString();
            if(row.op.OperandType is OperandType.InlineField or OperandType.InlineMethod or OperandType.InlineTok or OperandType.InlineType) {int token=BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(row.operand,4));try{return method.Module.ResolveMember(token)?.ToString()??$"token:{token:X8}";}catch{return $"token:{token:X8}";}}
            if(row.op.OperandType==OperandType.InlineString)return "string-token";
            return row.op.OperandType==OperandType.InlineNone?"":Convert.ToHexString(bytes.AsSpan(row.operand,row.end-row.operand));
        }
        var stores=new List<object>();
        for(int i=1;i<rows.Count;i++) {
            var row=rows[i];if(!row.op.Name!.StartsWith("stloc"))continue;
            int local=Index(row);var t=body.LocalVariables[local].LocalType;var prev=rows.Take(i).Last(r=>r.op!=OpCodes.Nop);
            if(t.IsValueType&&!t.IsPrimitive&&!t.IsEnum&&prev.op.Name!.StartsWith("ldc.i4"))stores.Add(new{store_il=row.offset,producer_il=prev.offset,producer=prev.op.Name,local,type=t.FullName});
        }
        summary.Add(new{assembly=pair.Item1,type=pair.Item2,method=method.Name,token=method.MetadataToken,body_sha256=Hash(bytes),body_bytes=bytes.Length,instructions=rows.Count,suspicious_scalar_to_aggregate_stores=stores});
        details.Add(new{type=pair.Item2,method=method.Name,locals=body.LocalVariables.Select(v=>new{v.LocalIndex,type=v.LocalType.ToString()}),instructions=rows.Select(r=>new{r.offset,op=r.op.Name,operand=Operand(r)})});
    }
}
var options=new JsonSerializerOptions{WriteIndented=true};
File.WriteAllText(Guard($"analysis/il2cpp/diagnostic-delta-cil-{run}.json"),JsonSerializer.Serialize(details,options));
File.WriteAllText(Guard($"reports/diagnostic-delta-cil-{run}.json"),JsonSerializer.Serialize(new{status="READ_ONLY_CIL_OPERAND_OBSERVATIONS",run,assemblies_loaded_without_execution=true,methods=summary,scope="Selected unchanged CIL only; scalar-to-aggregate stores are observed operand-type defects, not verified whole-method semantics. No proprietary method bodies appear in this report."},options));
Console.WriteLine($"Observed {summary.Count} selected method bodies without execution");
