using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length != 2 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$")) throw new ArgumentException("Verified USB root and recovery run required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1];
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? directory = new(Path.GetDirectoryName(path)!); directory != null; directory = directory.Parent)
        if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
string FileHash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
var ops = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(field => field.FieldType == typeof(OpCode))
    .Select(field => (OpCode)field.GetValue(null)!).ToDictionary(op => unchecked((ushort)op.Value));
List<Row> Decode(byte[] bytes)
{
    var result = new List<Row>();
    for (int at = 0; at < bytes.Length;)
    {
        int start = at;
        ushort code = bytes[at++]; if (code == 0xFE) code = (ushort)(0xFE00 | bytes[at++]);
        var op = ops[code]; int operand = at;
        at += op.OperandType switch
        {
            OperandType.InlineNone => 0,
            OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
            OperandType.InlineVar => 2, OperandType.InlineI8 or OperandType.InlineR => 8,
            OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at, 4)), _ => 4
        };
        if (at > bytes.Length) throw new Exception("Truncated instruction");
        result.Add(new(start, operand, at, op));
    }
    return result;
}
int Index(Row row, byte[] bytes) => row.Op.OperandType == OperandType.InlineNone ? int.Parse(row.Op.Name![^1..])
    : row.Op.OperandType == OperandType.ShortInlineVar ? bytes[row.Operand]
    : BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(row.Operand, 2));
bool IsLocalLoad(Row row) => row.Op.Name!.StartsWith("ldloc", StringComparison.Ordinal);
bool IsLocalStore(Row row) => row.Op.Name!.StartsWith("stloc", StringComparison.Ordinal);
bool IsArgumentLoad(Row row) => row.Op.Name!.StartsWith("ldarg", StringComparison.Ordinal);

string? fatal = null, originalBodyHash = null, sliceHash = null, inputBoundary = null;
int boxInstructions = 0, diagnosticStrings = 0, cases = 0, checks = 0, expressionStart = -1, expressionEnd = -1;
var copyChain = new List<object>();
var assemblyPath = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp.dll");
var nativePath = Guard("analysis/nso/main-uncompressed.nso");
const string nativeSha256 = "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968";
string? nativeWindowHash = null;
string? provenanceHash = null;
try
{
    var provenancePath = Guard("reports/boxing-input-provenance-v29.json");
    using var provenance = JsonDocument.Parse(File.ReadAllText(provenancePath));
    var evidence = provenance.RootElement;
    if (evidence.GetProperty("status").GetString() != "PASS_SCOPED_NATIVE_BOX_ARGUMENT_TYPE_PROVENANCE"
        || evidence.GetProperty("selected_native_type").GetString() != "System.Int32"
        || evidence.GetProperty("selected_typed_source_address").GetString() != "System.Int32"
        || evidence.GetProperty("primitive_boxed_size").GetInt32() != 20
        || evidence.GetProperty("primitive_payload_size").GetInt32() != 4
        || evidence.GetProperty("primitive_has_static_constructor").GetBoolean())
        throw new Exception("Independent native primitive identity/layout witness differs");
    provenanceHash = FileHash(provenancePath);
    if (FileHash(nativePath) != nativeSha256) throw new Exception("Original NSO hash differs");
    using (var stream = File.OpenRead(nativePath))
    {
        byte[] native = new byte[24]; stream.Position = 0x100 + 0xF23130; stream.ReadExactly(native);
        if (Convert.ToHexString(native).ToLowerInvariant() != "f30f00b9a85201d008d545f9000140f9e1330091cbdff097")
            throw new Exception("Native age stack/type/boxing witness differs");
        nativeWindowHash = Hash(native);
        if (nativeWindowHash != evidence.GetProperty("native_input_window_sha256").GetString())
            throw new Exception("Independent native argument witness differs");
        byte[] move = new byte[4]; stream.Position = 0x100 + 0xF23110; stream.ReadExactly(move);
        if (Convert.ToHexString(move).ToLowerInvariant() != "f303012a") throw new Exception("Native argument copy witness differs");
    }
    var assembly = Assembly.LoadFrom(assemblyPath);
    var method = assembly.GetType("FyberPlugin.User", true)!.GetMethod("SetAge", BindingFlags.Public | BindingFlags.Static, [typeof(int)])!;
    if (method == null || method.ReturnType != typeof(void) || !method.GetParameters().Select(parameter => parameter.ParameterType).SequenceEqual([typeof(int)]))
        throw new Exception("Actual method signature differs from native caller argument witness");
    var body = method.GetMethodBody()!;
    if (body.ExceptionHandlingClauses.Count != 0) throw new Exception("Unexpected EH region in selected method");
    var bytes = body.GetILAsByteArray()!;
    originalBodyHash = Hash(bytes);
    var decoded = Decode(bytes);
    int Token(Row row) => BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(row.Operand, 4));
    var boxes = decoded.Where(row => row.Op == OpCodes.Box && method.Module.ResolveType(Token(row)) == typeof(int)).ToArray();
    boxInstructions = boxes.Length;
    diagnosticStrings = decoded.Count(row => row.Op == OpCodes.Ldstr && method.Module.ResolveString(Token(row)) == "Method not found @B5B070");
    if (boxes.Length != 1) throw new Exception($"Expected one actual recovered Int32 box, observed {boxes.Length}; legacy helper diagnostics {diagnosticStrings}");
    if (diagnosticStrings != 0) throw new Exception("Legacy unresolved boxing diagnostic survived");
    var target = boxes[0];
    int targetIndex = decoded.IndexOf(target);
    var nodes = decoded.Select((row, index) => (row.Start, index)).ToDictionary(pair => pair.Start, pair => pair.index);
    var predecessors = decoded.Select(_ => new HashSet<int>()).ToArray();
    var successors = decoded.Select(_ => new HashSet<int>()).ToArray();
    for (int node = 0; node < decoded.Count; node++)
    {
        var row = decoded[node];
        void Edge(int offset)
        {
            if (!nodes.TryGetValue(offset, out int destination)) throw new Exception("Invalid original CIL branch target");
            successors[node].Add(destination); predecessors[destination].Add(node);
        }
        if (row.Op.OperandType == OperandType.InlineSwitch)
        {
            int count = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(row.Operand, 4));
            for (int index = 0; index < count; index++) Edge(row.End + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(row.Operand + 4 + index * 4, 4)));
        }
        else if (row.Op.OperandType is OperandType.InlineBrTarget or OperandType.ShortInlineBrTarget)
            Edge(row.End + (row.Op.OperandType == OperandType.InlineBrTarget
                ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(row.Operand, 4)) : unchecked((sbyte)bytes[row.Operand])));
        if (row.Op.FlowControl is not (FlowControl.Branch or FlowControl.Return or FlowControl.Throw) && node + 1 < decoded.Count)
            Edge(decoded[node + 1].Start);
    }
    var reachable = new HashSet<int>(); var queue = new Queue<int>(); queue.Enqueue(0);
    while (queue.TryDequeue(out int node)) if (reachable.Add(node)) foreach (int next in successors[node]) queue.Enqueue(next);
    if (!reachable.Contains(targetIndex)) throw new Exception("Selected original box is unreachable from method entry");
    var dominators = decoded.Select((_, node) => node == 0 ? new HashSet<int> { 0 } : new HashSet<int>(reachable)).ToArray();
    bool changed;
    do
    {
        changed = false;
        foreach (int node in reachable.Where(node => node != 0))
        {
            var next = new HashSet<int>(reachable);
            foreach (int predecessor in predecessors[node].Where(reachable.Contains)) next.IntersectWith(dominators[predecessor]);
            next.Add(node);
            if (!next.SetEquals(dominators[node])) { dominators[node] = next; changed = true; }
        }
    } while (changed);
    var previous = decoded.Take(targetIndex).Last(row => row.Op != OpCodes.Nop);
    Row load;
    if (previous.Op == OpCodes.Ldobj)
    {
        if (method.Module.ResolveType(Token(previous)) != typeof(int)) throw new Exception("Unexpected boxed storage load type");
        load = decoded.Take(decoded.IndexOf(previous)).Last(row => row.Op != OpCodes.Nop);
    }
    else load = previous;
    int? inputLocal = null;
    if (IsLocalLoad(load))
    {
        int slot = Index(load, bytes);
        if (body.LocalVariables[slot].LocalType != typeof(int) || body.LocalVariables[slot].IsPinned)
            throw new Exception("Box input storage is not an ordinary typed Int32 local");
        inputLocal = slot;
        var seen = new HashSet<int>();
        void Trace(int local, int before)
        {
            if (!seen.Add(local)) throw new Exception("Input copy chain cycle");
            var writes = decoded.Where(row => IsLocalStore(row) && Index(row, bytes) == local).ToArray();
            if (writes.Length != 1 || writes[0].Start >= before) throw new Exception("Input local lacks a unique preceding assignment");
            var store = writes[0];
            if (!dominators[nodes[before]].Contains(nodes[store.Start])) throw new Exception("Input assignment does not dominate its original use");
            if (decoded.Any(row => row.Start < target.Start && row.Start != load.Start
                && (row.Op.Name is "ldloca" or "ldloca.s") && Index(row, bytes) == local))
                throw new Exception("Input local address escapes before the selected boxing expression");
            var source = decoded.Take(decoded.IndexOf(store)).Last(row => row.Op != OpCodes.Nop);
            if (IsArgumentLoad(source) && source.Op.Name is not ("ldarga" or "ldarga.s") && Index(source, bytes) == 0)
                copyChain.Add(new { local, source = "actual age argument 0", load_il_offset = source.Start, store_il_offset = store.Start });
            else if (IsLocalLoad(source) && source.Op.Name is not ("ldloca" or "ldloca.s"))
            {
                int from = Index(source, bytes);
                if (body.LocalVariables[from].LocalType != typeof(int)) throw new Exception("Non-Int32 input copy source");
                Trace(from, source.Start);
                copyChain.Add(new { local, source = "typed local " + from, load_il_offset = source.Start, store_il_offset = store.Start });
            }
            else throw new Exception("Box input assignment is not an exact typed copy of age argument");
        }
        Trace(slot, load.Start);
        inputBoundary = "actual typed Int32 local " + slot + "; unique copy chain from actual age argument 0";
    }
    else if (IsArgumentLoad(load) && Index(load, bytes) == 0)
        inputBoundary = "actual age argument 0";
    else throw new Exception("Box input expression is not a proven scalar argument or typed copy");
    if (decoded.Any(row => row.Start < target.Start && row.Start != load.Start
        && (row.Op.Name is "starg" or "starg.s" or "ldarga" or "ldarga.s") && Index(row, bytes) == 0))
        throw new Exception("Original age argument is modified or its address escapes before the selected expression");
    expressionStart = load.Start; expressionEnd = target.End;
    var selected = decoded.Where(row => row.Start >= expressionStart && row.End <= expressionEnd).ToArray();
    if (selected.Any(row => row.Start != load.Start && row.Op != OpCodes.Nop && row.Op != OpCodes.Ldobj && row.Op != OpCodes.Box))
        throw new Exception("Box slice contains extra operations");
    var slice = bytes.AsSpan(expressionStart, expressionEnd - expressionStart).ToArray();
    sliceHash = Hash(slice);
    var dynamic = new DynamicMethod("ActualRecoveredInt32BoxExpression", typeof(object), [typeof(int)], typeof(Program).Module, true);
    var info = dynamic.GetDynamicILInfo();
    var signature = SignatureHelper.GetLocalVarSigHelper();
    foreach (var local in body.LocalVariables) signature.AddArgument(local.LocalType, local.IsPinned);
    info.SetLocalSignature(signature.GetSignature());
    foreach (var row in selected.Where(row => row.Op == OpCodes.Ldobj || row.Op == OpCodes.Box))
    {
        if (method.Module.ResolveType(Token(row)) != typeof(int)) throw new Exception("Selected slice uses a foreign type token");
        BinaryPrimitives.WriteInt32LittleEndian(slice.AsSpan(row.Operand - expressionStart, 4), info.GetTokenFor(typeof(int).TypeHandle));
    }
    byte[] prefix = inputLocal is int input ? [0x02, 0xFE, 0x0E, (byte)input, (byte)(input >> 8)] : [];
    info.SetCode(prefix.Concat(slice).Concat(new byte[] { 0x2A }).ToArray(), Math.Max(1, body.MaxStackSize));
    var action = dynamic.CreateDelegate<Func<int, object>>();
    int[] edges = [0, 1, -1, int.MinValue, int.MaxValue, 127, 128, 255, 256, -128, -129, 32767, 32768, -32768, -32769, unchecked((int)0xA5A5A5A5)];
    var random = new Random(0xF23144);
    var values = edges.Concat(Enumerable.Range(0, 64).Select(_ => unchecked((int)random.NextInt64(0, 0x1_0000_0000L))));
    foreach (int value in values)
    {
        var first = action(value); var second = action(value);
        if (first == null || second == null || first.GetType() != typeof(int) || second.GetType() != typeof(int)) throw new Exception("Boxed type identity differs");
        checks++;
        if ((int)first != value || (int)second != value) throw new Exception("Boxed payload bits differ");
        checks++;
        if (ReferenceEquals(first, second)) throw new Exception("Box reused object identity");
        checks++; cases++;
    }
}
catch (Exception exception) { fatal = exception.GetType().FullName + ": " + exception.Message; }
var report = new { status = fatal == null && cases == 80 ? "PASS_RECOVERED_INT32_BOX_EXPRESSION_AT_TYPED_VALUE_BOUNDARY" : "RECOVERED_PRIMITIVE_BOX_LIMITATION",
    assembly_sha256 = FileHash(assemblyPath),
    recovery_run = run, cases, checks, caller = "FyberPlugin.User::SetAge(System.Int32)", caller_rva = "0xF230F0", boxing_call_rva = "0xF23144",
    native_source_sha256 = nativeSha256, native_input_window_sha256 = nativeWindowHash, native_input_storage = "W1 -> W19 -> [SP+0xC]",
    input_type_provenance_report_sha256 = provenanceHash,
    native_type_info_slot = "0x3979BA8", box_instructions = boxInstructions, legacy_box_diagnostic_strings = diagnosticStrings,
    input_boundary = inputBoundary, input_copy_chain = copyChain, original_body_il_sha256 = originalBodyHash, selected_expression_sha256 = sliceHash,
    expression_start_il_offset = expressionStart, expression_end_il_offset = expressionEnd, fatal,
    original_native_executed = false, runtime_helpers_replaced = 0, whole_game_source_ready = false,
    scope = "Execute only the actual recovered Int32 box expression from the chosen present native caller. Require exact original native argument-copy/stack/type-slot/call witnesses, actual method argument signature, exact host CLR Int32 box type token and a unique typed copy chain whose stores dominate their original uses when a local supplies the value. Reject escaping addresses or modified input arguments. The original expression instructions are retained; only exact Int32 type tokens map to the same CLR type, one proven Int32 local may be supplied at its declared value boundary, and a return is appended. Check signed/raw-bit payload, boxed type identity and fresh object identity. Original native boxing runtime allocation/GC, metadata initialization, the remainder of SetAge, other primitive/nullable/ref/enum/custom types and Switch feature availability are outside this scope." };
File.WriteAllText(Guard($"reports/recovered-primitive-box-{run}.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(report));
return fatal == null ? 0 : 1;

sealed record Row(int Start, int Operand, int End, OpCode Op);
