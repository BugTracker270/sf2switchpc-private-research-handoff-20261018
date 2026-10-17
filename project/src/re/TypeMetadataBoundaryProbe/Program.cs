using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
if (!string.Equals(root, @"F:\SF2SwitchPC", StringComparison.OrdinalIgnoreCase)) throw new IOException("Unexpected USB workspace");
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? directory = new(Path.GetDirectoryName(path)!); directory != null; directory = directory.Parent)
        if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var checks = new List<(string Name, bool Passed)>();
var observations = new List<object>();
void Check(string name, bool passed) => checks.Add((name, passed));
// These are observations of host metadata APIs, not a replacement implementation for Class::Init.
void ObserveMetadata(Type type, string phase)
{
    var handle = type.TypeHandle;
    var actual = Type.GetTypeFromHandle(handle);
    var initializer = actual!.TypeInitializer;
    var fields = actual.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
    var methods = actual.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
    var constructors = actual.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
    Check(phase + " " + type.Name + " metadata identity", ReferenceEquals(type, actual) && handle.Value != IntPtr.Zero);
    observations.Add(new { phase, type = actual.FullName, exact_type_identity = ReferenceEquals(type, actual),
        element = actual.GetElementType()?.FullName, base_type = actual.BaseType?.FullName,
        rank = actual.IsArray ? actual.GetArrayRank() : 0, actual.IsSZArray,
        static_initializer_present = initializer != null, field_count = fields.Length,
        method_count = methods.Length, constructor_count = constructors.Length,
        counted_cctor_runs = WitnessState.CountedRuns, throwing_cctor_runs = WitnessState.ThrowingRuns });
}
Check("counter canaries begin uninitialized", WitnessState.CountedRuns == 0 && WitnessState.ThrowingRuns == 0);
Check("both canaries declare precise explicit type initializers", typeof(CountedElement).TypeInitializer != null
    && typeof(ThrowingElement).TypeInitializer != null
    && (typeof(CountedElement).Attributes & TypeAttributes.BeforeFieldInit) == 0
    && (typeof(ThrowingElement).Attributes & TypeAttributes.BeforeFieldInit) == 0);
for (int iteration = 0; iteration < 8; iteration++)
{
    foreach (var type in new[] { typeof(byte[]), typeof(CountedElement), typeof(CountedElement[]), typeof(ThrowingElement), typeof(ThrowingElement[]) })
        ObserveMetadata(type, "before-positive-control-" + iteration);
    Check("metadata queries do not run either .cctor, iteration " + iteration, WitnessState.CountedRuns == 0 && WitnessState.ThrowingRuns == 0);
}
Check("byte array has exact primitive/SZArray identity and no .cctor", typeof(byte[]).IsSZArray
    && typeof(byte[]).GetElementType() == typeof(byte) && typeof(byte[]).BaseType == typeof(Array)
    && typeof(byte[]).TypeInitializer == null && typeof(byte).TypeInitializer == null);
var bytes = new byte[3];
Check("ready byte-array runtime supports real typed storage", bytes.GetType() == typeof(byte[]) && bytes.Length == 3);
bytes[1] = 0xA7;
Check("actual byte-array typed write/read", bytes[1] == 0xA7);
int preControlObservations = observations.Count;
var runsBeforeControls = new { counted = WitnessState.CountedRuns, throwing = WitnessState.ThrowingRuns };
// Positive controls prove the canaries really detect constructor execution.
RuntimeHelpers.RunClassConstructor(typeof(CountedElement).TypeHandle);
Check("explicit counted .cctor positive control runs once", WitnessState.CountedRuns == 1 && CountedElement.Value == 17);
bool throwingControl = false;
try { RuntimeHelpers.RunClassConstructor(typeof(ThrowingElement).TypeHandle); }
catch (TypeInitializationException error) { throwingControl = error.InnerException is InvalidOperationException inner && inner.Message == "cctor-canary"; }
Check("explicit throwing .cctor positive control fails with expected exception", throwingControl && WitnessState.ThrowingRuns == 1);
foreach (var type in new[] { typeof(CountedElement), typeof(CountedElement[]), typeof(ThrowingElement), typeof(ThrowingElement[]) })
    ObserveMetadata(type, "after-positive-control");
Check("metadata observation after failed .cctor does not rerun or throw it", WitnessState.CountedRuns == 1 && WitnessState.ThrowingRuns == 1);
var report = new
{
    status = checks.All(check => check.Passed) ? "PASS_HOST_METADATA_OBSERVATION_WITH_CCTOR_CANARIES" : "FAIL_HOST_METADATA_OBSERVATION_WITH_CCTOR_CANARIES",
    checks = checks.Count, failures = checks.Count(check => !check.Passed),
    tests = checks.Select(check => new { name = check.Name, passed = check.Passed }), observations,
    metadata_observation_count = observations.Count, pre_control_metadata_observations = preControlObservations,
    cctor_runs_before_positive_controls = runsBeforeControls,
    cctor_runs_after_positive_controls = new { counted = WitnessState.CountedRuns, throwing = WitnessState.ThrowingRuns },
    candidate_first_type = "System.Byte[]", candidate_translation_implemented = false,
    original_il2cpp_source_report_sha256 = Hash(Guard("reports/class-layout-runtime-source-v37.json")),
    actual_runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
    corelib_sha256 = Hash(typeof(object).Assembly.Location), probe_source_sha256 = Hash(Guard("src/re/TypeMetadataBoundaryProbe/Program.cs")),
    core_built = false, core_edited = false, original_game_code_executed = false,
    scope = "BCL-only host CLR observations of typeof/TypeHandle/GetTypeFromHandle and reflection member metadata. Forty observations precede deliberate .cctor positive controls, including reference-element arrays and a throwing constructor. These APIs leave both canaries untouched; explicit RunClassConstructor is tested separately to prove the canaries. No native cold initialization, metadata helper replacement, production lowering, type-loader failure equivalence or game invocation is implemented."
};
File.WriteAllText(Guard("reports/clr-type-metadata-boundary-v37.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + Environment.NewLine);
Console.WriteLine(JsonSerializer.Serialize(new { report.status, report.checks, report.failures, report.metadata_observation_count }));
return report.failures == 0 ? 0 : 1;

static class WitnessState
{
    public static int CountedRuns;
    public static int ThrowingRuns;
}
sealed class CountedElement
{
    public static readonly int Value = 17;
    static CountedElement() { WitnessState.CountedRuns++; }
}
sealed class ThrowingElement
{
    static ThrowingElement() { WitnessState.ThrowingRuns++; throw new InvalidOperationException("cctor-canary"); }
}
