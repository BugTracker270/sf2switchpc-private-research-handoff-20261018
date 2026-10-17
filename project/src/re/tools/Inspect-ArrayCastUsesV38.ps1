param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference='Stop'
$Root=[IO.Path]::GetFullPath($Root).TrimEnd('\','/')
function TaskPath([string]$relative) {
    $p = [IO.Path]::GetFullPath([IO.Path]::Combine($Root,$relative))
    if (-not $p.StartsWith($Root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Outside USB' }
    $d = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($p))
    while ($null -ne $d) { if ($d.Exists -and ($d.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse' }; $d=$d.Parent }
    return $p
}
$folder=TaskPath 'src/re/VirtualCompanionProductionProbe/bin/Release/net10.0'
$core=[IO.Path]::Combine($folder,'Cpp2IL.Core.dll')
if((Get-FileHash -LiteralPath $core -Algorithm SHA256).Hash.ToLowerInvariant()-ne'197403735d374bdde681ad203cdb3eb18e8cd9eef01897908a8c4f9e786ad99a'){throw'Frozen Core mismatch'}
$handler=[Func[System.Runtime.Loader.AssemblyLoadContext,System.Reflection.AssemblyName,System.Reflection.Assembly]] { param($context,$name); $p=[IO.Path]::Combine($folder,$name.Name+'.dll'); if([IO.File]::Exists($p)) { return $context.LoadFromAssemblyPath($p) }; return $null }
[System.Runtime.Loader.AssemblyLoadContext]::Default.add_Resolving($handler)
[void][Reflection.Assembly]::LoadFrom($core);[void][Reflection.Assembly]::LoadFrom([IO.Path]::Combine($folder,'AssetRipper.Primitives.dll'))
$env:CPP2IL_LEGACY_HFA='1'
[Cpp2IL.Core.Cpp2IlApi]::Init((TaskPath 'analysis/empty-probe-plugins'))
[Cpp2IL.Core.Cpp2IlApi]::InitializeLibCpp2Il((TaskPath 'unpacked/effective/exefs/main'),(TaskPath 'unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat'),[AssetRipper.Primitives.UnityVersion]::new(2018,1,9,[AssetRipper.Primitives.UnityVersionType]::Final,1))
$app=[Cpp2IL.Core.Cpp2IlApi]::CurrentAppContext
$typeMap=@{}; foreach($a in $app.Assemblies) { foreach($t in $a.Types) { $typeMap[$a.Name+'|'+$t.FullName]=$t } }
$groups=Get-Content -LiteralPath(TaskPath 'analysis/reconstruction/compiler-family-v38/array-cast-owner-candidates.json') -Raw|ConvertFrom-Json
$results=[Collections.Generic.List[object]]::new();$processed=0
foreach($group in $groups){
 $processed++;$record=[ordered]@{source=$group.source;declaration_line=$group.declaration_line;assembly=$group.assembly;type=$group.type;method=$group.method;diagnostic_occurrences=$group.diagnostic_occurrences;diagnostic_types=$group.diagnostic_types;all_casts_simple=$group.all_casts_simple;status='UNRESOLVED_SOURCE_OWNER_OR_IR';registered_rva=$null;helper_calls=0;genuine_runtime_class_projections=0;genuine_array_types=@();direct_array_phantom_captures=0;error=$null}
 try{
  $type=$typeMap[$group.assembly+'|'+$group.type]
  if($null-eq$type-or$null-eq$group.method){throw'Unresolved original type/method candidate'}
  $matches=@($type.Methods|Where-Object{$_.Name-eq$group.method-and$_.Parameters.Count-eq$group.parameter_count})
  if($matches.Count-ne1){throw'Ambiguous original method candidate'}
  $method=$matches[0];$record.registered_rva=('0x{0:X}'-f$method.UnderlyingPointer)
  $method.Analyze()
  $instructions=@($method.ControlFlowGraph.Instructions);$defs=@{}
  foreach($row in $instructions){if($row.Destination-is[Cpp2IL.Core.ISIL.LocalVariable]){if(-not$defs.ContainsKey($row.Destination)){$defs[$row.Destination]=[Collections.Generic.List[object]]::new()};$defs[$row.Destination].Add($row)}}
  function FindLoad([object]$operand,[int]$expected){
   $visited=[Collections.Generic.HashSet[object]]::new()
   for($depth=0;$depth-lt32;$depth++){
    if($operand-is[Cpp2IL.Core.ISIL.MemoryOperand]){if($null-eq$operand.Index-and$operand.Scale-eq0-and$operand.Addend-eq$expected){return [pscustomobject]@{memory=$operand;defining=$null}};return $null}
    if($operand-isnot[Cpp2IL.Core.ISIL.LocalVariable]-or-not$visited.Add($operand)-or-not$defs.ContainsKey($operand)-or$defs[$operand].Count-ne1){return $null}
    $definition=$defs[$operand][0]
    if($definition.OpCode.ToString()-ne'Move'-or$definition.Operands.Count-ne2){return $null}
    $source=$definition.Operands[1]
    if($source-is[Cpp2IL.Core.ISIL.MemoryOperand]){if($null-eq$source.Index-and$source.Scale-eq0-and$source.Addend-eq$expected){return [pscustomobject]@{memory=$source;defining=$definition}};return $null}
    if($source-isnot[Cpp2IL.Core.ISIL.LocalVariable]){return $null};$operand=$source
   };return $null
  }
  $classes=[Collections.Generic.HashSet[object]]::new();$arrayTypes=[Collections.Generic.List[string]]::new()
  foreach($call in $instructions){
   if($call.OpCode.ToString()-ne'Call'-or$call.Operands.Count-ne18-or$call.Operands[0]-isnot[Cpp2IL.Core.ISIL.Immediate]-or$call.Operands[0].UnsignedValue-ne0xB5B390){continue}
   $record.helper_calls++
   for($i=4;$i-lt$call.Operands.Count;$i++){if($call.Operands[$i]-is[Cpp2IL.Core.ISIL.LocalVariable]-and$call.Operands[$i].Type-is[Cpp2IL.Core.Model.Contexts.SzArrayTypeAnalysisContext]){$record.direct_array_phantom_captures++}}
   $element=FindLoad $call.Operands[3] 0x40
   if($null-eq$element){continue};$klass=FindLoad $element.memory.Base 0
   if($null-eq$klass-or$null-eq$klass.defining-or$klass.memory.Base-isnot[Cpp2IL.Core.ISIL.LocalVariable]-or$klass.memory.Base.Type-isnot[Cpp2IL.Core.Model.Contexts.SzArrayTypeAnalysisContext]){continue}
   if($classes.Add($klass.defining)){$arrayTypes.Add($klass.memory.Base.Type.FullName)}
  }
  $record.genuine_runtime_class_projections=$classes.Count;$record.genuine_array_types=@($arrayTypes)
  $record.status='READ_ONLY_ACTUAL_EMITTER_INPUT_ARRAY_CLASS_AND_CAPTURE_OBSERVATIONS'
 }catch{$record.error=$_.Exception.GetType().FullName+': '+$_.Exception.Message}
 $results.Add([pscustomobject]$record)
 if($processed%50-eq0){Write-Output('Observed '+$processed+'/'+$groups.Count)}
}
$target=TaskPath 'analysis/reconstruction/compiler-family-v38/array-cast-actual-ir-uses.json'
$results|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $target -Encoding utf8
[pscustomobject]@{status='READ_ONLY_FROZEN_V38_SELECTED_ARRAY_CAST_IR_USES';source_groups=$groups.Count;completed=$processed;frozen_core_sha256=(Get-FileHash -LiteralPath $core -Algorithm SHA256).Hash.ToLowerInvariant();private_results=$target.Substring($Root.Length+1);private_results_sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant();source_sha256=(Get-FileHash -LiteralPath(TaskPath 'src/re/tools/Inspect-ArrayCastUsesV38.ps1') -Algorithm SHA256).Hash.ToLowerInvariant();core_built=$false;game_or_native_functions_executed=0}|ConvertTo-Json|Set-Content -LiteralPath(TaskPath 'reports/array-cast-actual-ir-survey-v38.json') -Encoding utf8
Write-Output('Finished '+$processed)
