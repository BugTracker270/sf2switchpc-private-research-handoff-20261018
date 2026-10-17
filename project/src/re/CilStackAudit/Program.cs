using AsmResolver.DotNet;
using System.Text.Json;
using System.Text.RegularExpressions;

if(args.Length!=2||!Regex.IsMatch(args[1],"^[a-z0-9-]+$"))throw new ArgumentException("USB root and recovery run required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),run=args[1];
string Guard(string relative) {
    string path=Path.GetFullPath(Path.Combine(root,relative));
    if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB workspace");
    for(DirectoryInfo? dir=new(Path.GetDirectoryName(path)!);dir!=null;dir=dir.Parent)
        if(dir.Exists&&(dir.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point forbidden");
    return path;
}
string source=Guard($"analysis/il2cpp/cpp2il-recovery-{run}"),output=Guard($"analysis/il2cpp/cil-stack-audit-{run}");
if(Directory.Exists(output))throw new IOException("Preserve prior stack audit");Directory.CreateDirectory(output);
var assemblies=new List<object>();int bodies=0,understated=0,flowFailures=0,helperParents=0;
foreach(var file in Directory.GetFiles(source,"*.dll").Order()) {
    var module=ModuleDefinition.FromFile(file);int count=0,smallHeaders=0,failed=0,badHelpers=0;
    using var details=new StreamWriter(Guard($"analysis/il2cpp/cil-stack-audit-{run}/{Path.GetFileName(file)}.jsonl"));
    foreach(var type in module.GetAllTypes()) {
        if(type.Namespace=="Cpp2ILInjected"&&type.Name=="Cpp2ILHelpers"&&type.BaseType==null)badHelpers++;
        foreach(var method in type.Methods) {
            try {
                var body=method.CilMethodBody;if(body==null)continue;count++;
                int required=body.ComputeMaxStack();bool tooSmall=body.MaxStack<required;if(tooSmall)smallHeaders++;
                details.WriteLine(JsonSerializer.Serialize(new{method=method.FullName,declared=body.MaxStack,required,status=tooSmall?"UNDERSTATED_MAX_STACK":"DEPTH_ONLY_PASS"}));
            } catch(Exception ex) {
                failed++;details.WriteLine(JsonSerializer.Serialize(new{method=method.FullName,status="STACK_FLOW_OR_PARSE_FAILURE",error=ex.GetType().FullName+": "+ex.Message}));
            }
        }
    }
    bodies+=count;understated+=smallHeaders;flowFailures+=failed;helperParents+=badHelpers;
    assemblies.Add(new{file=Path.GetFileName(file),bodies=count,understated_max_stack=smallHeaders,stack_flow_failures=failed,helper_types_without_base=badHelpers});
}
var report=new{status=understated==0&&flowFailures==0&&helperParents==0?"PASS_STACK_DEPTH_AND_HEADERS_ONLY":"STACK_HEADER_OR_FLOW_LIMITATIONS_CONFIRMED",recovery_run=run,assembly_count=assemblies.Count,bodies,
    understated_max_stack=understated,stack_flow_failures=flowFailures,helper_types_without_base=helperParents,assemblies,
    scope="Pinned AsmResolver 6.0.1 stack-depth/control-flow calculation compared with serialized MaxStack headers; injected helper parent presence checked. Loaded assemblies are never executed or rewritten. This does not verify operand types, source correctness, runtime behavior, or whole-game recovery."};
string json=JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true});
File.WriteAllText(Guard($"analysis/il2cpp/cil-stack-audit-{run}/summary.json"),json+"\n");
File.WriteAllText(Guard($"reports/cil-stack-audit-{run}.json"),json+"\n");Console.WriteLine(json);
