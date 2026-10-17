param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath($Root).TrimEnd('\','/')
function TaskPath([string]$Relative) {
    $resolved = [IO.Path]::GetFullPath([IO.Path]::Combine($Root,$Relative))
    if (-not $resolved.StartsWith($Root + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Outside USB' }
    $parent = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($resolved))
    while ($null -ne $parent) { if ($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse point' }; $parent = $parent.Parent }
    return $resolved
}
function TaskHash([string]$Relative) { return (Get-FileHash -LiteralPath (TaskPath $Relative) -Algorithm SHA256).Hash.ToLowerInvariant() }
$frozenFolder = TaskPath 'src/re/VirtualCompanionProductionProbe/bin/Release/net10.0'
$frozenCore = [IO.Path]::Combine($frozenFolder,'Cpp2IL.Core.dll')
if ((Get-FileHash -LiteralPath $frozenCore -Algorithm SHA256).Hash.ToLowerInvariant() -ne '197403735d374bdde681ad203cdb3eb18e8cd9eef01897908a8c4f9e786ad99a') { throw 'Frozen v38 Core differs' }
$resolveHandler = [Func[System.Runtime.Loader.AssemblyLoadContext,System.Reflection.AssemblyName,System.Reflection.Assembly]] {
    param($context,$name)
    $candidate = [IO.Path]::Combine($frozenFolder,$name.Name + '.dll')
    if ([IO.File]::Exists($candidate)) { return $context.LoadFromAssemblyPath($candidate) }
    return $null
}
[System.Runtime.Loader.AssemblyLoadContext]::Default.add_Resolving($resolveHandler)
[void][Reflection.Assembly]::LoadFrom($frozenCore)
[void][Reflection.Assembly]::LoadFrom([IO.Path]::Combine($frozenFolder,'AssetRipper.Primitives.dll'))
$env:CPP2IL_LEGACY_HFA = '1'
[Cpp2IL.Core.Cpp2IlApi]::Init((TaskPath 'analysis/empty-probe-plugins'))
$version = [AssetRipper.Primitives.UnityVersion]::new(2018,1,9,[AssetRipper.Primitives.UnityVersionType]::Final,1)
[Cpp2IL.Core.Cpp2IlApi]::InitializeLibCpp2Il((TaskPath 'unpacked/effective/exefs/main'),(TaskPath 'unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat'),$version)
$app = [Cpp2IL.Core.Cpp2IlApi]::CurrentAppContext
$keys = $app.GetOrCreateKeyFunctionAddresses()
$types = @($app.Assemblies | ForEach-Object { $_.Types })
$profile = @($types | Where-Object FullName -EQ 'InControl.PlayStation4MacBTProfile')[0]
$vector = @($types | Where-Object FullName -EQ 'Vector3f')[0]
$methods = @(@($profile.Methods | Where-Object Name -EQ '.ctor')[0], @($vector.Methods | Where-Object Name -EQ 'get_Length')[0])
$results = @()
$privateFolder = TaskPath 'analysis/reconstruction/compiler-family-v38/actual-ir'
[void][IO.Directory]::CreateDirectory($privateFolder)
foreach ($method in $methods) {
    $method.ConvertedIsil = $app.InstructionSet.GetIsilFromMethod($method)
    $method.ParameterOperands = $app.InstructionSet.GetParameterOperandsFromMethod($method)
    $method.ControlFlowGraph = [Cpp2IL.Core.Graphs.ISILControlFlowGraph]::new($method.ConvertedIsil)
    [Cpp2IL.Core.Analysis.StackAnalyzer]::Analyze($method)
    $method.DominatorInfo = [Cpp2IL.Core.Graphs.DominatorInfo]::new($method.ControlFlowGraph)
    [Cpp2IL.Core.Analysis.SsaForm]::Build($method)
    [Cpp2IL.Core.Analysis.LocalVariables]::CreateAll($method)
    [Cpp2IL.Core.Analysis.FlagConditionRecovery]::Run($method)
    [Cpp2IL.Core.Analysis.DeadCodeEliminator]::Run($method)
    $before = [string]::Join("`n",[string[]]@($method.ControlFlowGraph.Blocks | ForEach-Object { $_.ToString() }))
    $beforePath = [IO.Path]::Combine($privateFolder,('{0:X}-before-resolve.txt' -f $method.UnderlyingPointer))
    [IO.File]::WriteAllText($beforePath,$before)
    [Cpp2IL.Core.Analysis.MetadataResolver]::ResolveAll($method)
    [Cpp2IL.Core.Analysis.KeyFunctionRecovery]::Run($method)
    [Cpp2IL.Core.Analysis.DeadCodeEliminator]::Run($method)
    [Cpp2IL.Core.Analysis.MetadataInitGuardRemover]::Run($method)
    [Cpp2IL.Core.Analysis.WriteBarrierRecovery]::Run($method)
    [Cpp2IL.Core.Analysis.InjectedCheckRemover]::Run($method)
    [Cpp2IL.Core.Analysis.InterfaceDispatchRecovery]::Run($method)
    [Cpp2IL.Core.Analysis.LocalVariables]::ResolveTypesAndFields($method)
    $after = [string]::Join("`n",[string[]]@($method.ControlFlowGraph.Blocks | ForEach-Object { $_.ToString() }))
    $afterPath = [IO.Path]::Combine($privateFolder,('{0:X}-after-type.txt' -f $method.UnderlyingPointer))
    [IO.File]::WriteAllText($afterPath,$after)
    $helperCalls = @($method.ControlFlowGraph.Instructions | Where-Object { $_.OpCode.ToString() -EQ 'Call' -and $_.Operands.Count -gt 0 -and $_.Operands[0] -is [Cpp2IL.Core.ISIL.Immediate] -and $_.Operands[0].UnsignedValue -EQ 0xB5B390 })
    $results += [pscustomobject]@{ owner=$method.DeclaringType.FullName; method=$method.Name; registered_rva=('0x{0:X}' -f $method.UnderlyingPointer); numeric_isinst_calls=$helperCalls.Count; helper_operand_counts=@($helperCalls | ForEach-Object {$_.Operands.Count}); before_ir=$beforePath.Substring($Root.Length+1); before_sha256=(Get-FileHash -LiteralPath $beforePath -Algorithm SHA256).Hash.ToLowerInvariant(); after_ir=$afterPath.Substring($Root.Length+1); after_sha256=(Get-FileHash -LiteralPath $afterPath -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$targetAliases = @()
if ($app.MethodsByAddress.ContainsKey([uint64]0xB5B390)) { $targetAliases = @($app.MethodsByAddress[[uint64]0xB5B390] | ForEach-Object { $_.FullName }) }
$report = [ordered]@{ status='READ_ONLY_FROZEN_V38_OBJECT_ISINST_FINDER_AND_ACTUAL_IR'; core_sha256=(Get-FileHash -LiteralPath $frozenCore -Algorithm SHA256).Hash.ToLowerInvariant(); original_binary_sha256=(TaskHash 'unpacked/effective/exefs/main'); original_metadata_sha256=(TaskHash 'unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat'); discovered_object_is_inst=('0x{0:X}' -f $keys.il2cpp_vm_object_is_inst); native_B5B390_registered_aliases=$targetAliases; methods=$results; source_sha256=(TaskHash 'src/re/tools/Inspect-ObjectIsInstMechanism.ps1'); core_built=$false; original_game_methods_invoked=0; original_native_functions_executed=0; full_clean_decompile_ready=$false; scope='Existing frozen v38 analysis APIs invoked in a fresh PowerShell.NET10 process with inherited USB runtime environment; no initializer, source export, Core build, recovered CIL modification or game/native execution. Two original method SSA/type graphs and existing key-function discovery are observations only.' }
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (TaskPath 'reports/object-isinst-actual-ir-v38.json') -Encoding utf8
$report | Select-Object status,core_sha256,discovered_object_is_inst | ConvertTo-Json -Compress
