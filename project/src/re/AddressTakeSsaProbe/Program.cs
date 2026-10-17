using System.Security.Cryptography;
using System.Text.Json;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;

if(args.Length!=1)throw new ArgumentException("Verified USB root required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string p=Path.GetFullPath(Path.Combine(root,relative));
    if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");
    for(DirectoryInfo? d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)
        if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point forbidden");
    return p;
}
var observations=new List<object>();var tests=new List<object>();
void Check(string name,bool ok)=>tests.Add(new{name,status=ok?"PASS":"FAIL"});
foreach(string mode in new[]{"plain-read","memory-base-read","no-read","overwritten-before-read","call-address-then-read"})
{
    var slot=new Register(901,"stack_slot");var pointer=new Register(902,"X0");var output=new Register(903,"result");
    List<Instruction> code=[new(0,OpCode.Move,slot,new Immediate(0x51A7))];
    Instruction take=mode=="call-address-then-read"?new(1,OpCode.CallVoid,new Immediate(0x12345678),new AddressOf(slot)):new(1,OpCode.Move,pointer,new AddressOf(slot));
    code.Add(take);
    if(mode=="overwritten-before-read")code.Add(new(code.Count,OpCode.Move,slot,new Immediate(0x6A17)));
    Instruction? read=null;
    if(mode!="no-read")
    {
        read=new(code.Count,OpCode.Move,output,mode=="memory-base-read"?new MemoryOperand(slot,addend:8):slot);code.Add(read);
        code.Add(new(code.Count,OpCode.Return,output));
    }
    else code.Add(new(code.Count,OpCode.Return,new Immediate(0)));
    string[] before=code.Select(i=>i.ToString()).ToArray();
    var graph=new ISILControlFlowGraph(code);SsaForm.Build(graph,new DominatorInfo(graph));
    var initial=(Register)code[0].Destination!;
    var address=(Register)((AddressOf)take.Operands[mode=="call-address-then-read"?1:1]).Target;
    Register? consumed=read==null?null:read.Operands[1] is Register r?r:(Register)((MemoryOperand)read.Operands[1]).Base!;
    bool readTriggers=mode is "plain-read" or "memory-base-read" or "call-address-then-read";
    Check(mode+" address version",readTriggers?address.Version!=initial.Version:address.Version==initial.Version);
    if(readTriggers)Check(mode+" subsequent read uses new address version",consumed!.Value==address);
    if(mode=="overwritten-before-read")Check("overwrite supplies subsequent read",consumed==((Register)code[2].Destination!));
    observations.Add(new{mode,pure_address_creation=mode!="call-address-then-read",initializer=initial.ToString(),address_target=address.ToString(),later_read=consumed?.ToString(),
        initialization_reaches_address=initial==address,implicit_definition=take.ImplicitDefinition?.ToString(),before,
        after=graph.Instructions.Select(i=>i.ToString()).ToArray(),
        conclusion=readTriggers?(mode=="call-address-then-read"?"Actual byref call deliberately clobbers; caller input/storage linking needs separate alias reasoning.":"Pure address creation advances slot version without a write or call; prior initializer is disconnected from address target."):"Control: no later unoverwritten plain read, so address uses prior initializer version."});
}
string core=typeof(SsaForm).Assembly.Location;
var report=new{status=tests.All(t=>JsonSerializer.Serialize(t).Contains("PASS"))?"CONFIRMED_READ_DEPENDENT_PURE_ADDRESS_SSA_VERSION_LOSS":"PROBE_EXPECTATION_FAILED",checks=tests.Count,tests,observations,
    loaded_core_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(core))).ToLowerInvariant(),core_source_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Guard("refs/Cpp2IL/Cpp2IL.Core/Analysis/SsaForm.cs")))).ToLowerInvariant(),
    scope="Calls existing compiled SsaForm.Build on original minimal ISIL fixtures. Direct DLL reference has no Core project/build writes. Demonstrates pure address creation with a later plain or memory-base read; address-only successors do not trigger this behavior. Does not establish actual SetStage lowering or propose suppressing real byref call writes."};
File.WriteAllText(Guard("reports/address-take-ssa-version-loss-v31.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+Environment.NewLine);
Console.WriteLine(JsonSerializer.Serialize(report));
return tests.All(t=>JsonSerializer.Serialize(t).Contains("PASS"))?0:1;
