using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;

if (args.Length != 1) throw new ArgumentException("USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative) { string path = Path.GetFullPath(Path.Combine(root, relative)); if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB"); for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent) if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point"); return path; }
string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
const string run = "nso-virtual-companion-copy-v38";
string relative = $"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp.dll";
byte[] image = File.ReadAllBytes(Guard(relative));
using var runtime = JsonDocument.Parse(File.ReadAllText(Guard($"reports/recovered-xml-attribute-runtime-{run}.json")));
if (runtime.RootElement.GetProperty("assembly_sha256").GetString() != Hash(image)) throw new InvalidDataException("Runtime assembly hash mismatch");
using var stream = new MemoryStream(image, false); using var pe = new PEReader(stream); var metadata = pe.GetMetadataReader();
var modules = metadata.TypeDefinitions.Where(handle => metadata.GetString(metadata.GetTypeDefinition(handle).Name) == "<Module>").ToArray();
if (modules.Length != 1) throw new InvalidDataException("Unique global module type required");
var global = metadata.GetTypeDefinition(modules[0]);
var methods = global.GetMethods().Select(handle => { var definition = metadata.GetMethodDefinition(handle); return new { token = $"0x{MetadataTokens.GetToken(handle):X8}", name = metadata.GetString(definition.Name), attributes = definition.Attributes.ToString(), rva = definition.RelativeVirtualAddress }; }).ToArray();
bool absent = methods.All(method => method.name != ".cctor");
var report = new { status = absent ? "PASS_ORIGINAL_V38_MODULE_INITIALIZER_ABSENT_METADATA_ONLY" : "MODULE_INITIALIZER_PRESENT", recovery_run = run, assembly = relative, assembly_sha256 = Hash(image), module_type_token = $"0x{MetadataTokens.GetToken(modules[0]):X8}", global_methods = methods, global_type_initializer_count = methods.Count(m => m.name == ".cctor"), owner_type_initializer_absence_already_proved = runtime.RootElement.GetProperty("recovered_type_initializer_absent_required").GetBoolean(), runtime_report_sha256 = Hash(File.ReadAllBytes(Guard($"reports/recovered-xml-attribute-runtime-{run}.json"))), source_sha256 = Hash(File.ReadAllBytes(Guard("src/re/ModuleInitializerInventoryProbe/Program.cs"))), assemblies_loaded = 0, original_methods_invoked = 0, scope = "Metadata-only PEReader inspection of exact unchanged Assembly-CSharp.dll already exercised by the host XML helper gate. The unique <Module> type has no .cctor; no global initializer can be supplied by this module. Original XmlExtensions .cctor absence is separately required in the frozen runtime report. This does not certify arbitrary referenced assemblies or whole-game initialization." };
File.WriteAllText(Guard("reports/recovered-xml-attribute-module-initializer-v38.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n"); Console.WriteLine(JsonSerializer.Serialize(new { report.status, report.global_type_initializer_count, global_methods = methods.Length })); return absent ? 0 : 2;
