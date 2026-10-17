"""Save a reproducible experimental tool patch without replacing the canonical patch."""
import argparse
import re
import difflib
import hashlib
import json
import subprocess
from package_cpp2il_corrections import ROOT, PIN, FILES
from usb_boundary import destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-label', help='Save a separate unpromoted candidate without replacing the current experiment')
    args = parser.parse_args()
    if args.artifact_label is not None and not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', args.artifact_label):
        parser.error('artifact label must be 1-64 lowercase letters, digits or hyphens')
    suffix = '-' + args.artifact_label if args.artifact_label else ''
    repo = ROOT / 'refs/Cpp2IL'
    if subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('Unexpected tool checkout')
    names = FILES + ['Cpp2IL.Core/Utils/LegacyArm64Hfa.cs',
                     'Cpp2IL.Core/OutputFormats/AsmResolverDllOutputFormatIlRecovery.cs',
                     'Cpp2IL.Core/Analysis/LegacyArm64FieldPaths.cs',
                     'Cpp2IL.Core/ISIL/MemoryOperand.cs',
                     'Cpp2IL.Core/ISIL/FieldReference.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64LeafAccessors.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64AggregateLeaves.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64ValueThisThunks.cs',
                     'Cpp2IL.Core/Model/Contexts/ApplicationAnalysisContext.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64ScalarBoxing.cs',
                     'Cpp2IL.Core/Analysis/KeyFunctionRecovery.cs',
                     'Cpp2IL.Core/Analysis/SsaSimplifier.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64CfgInitializationPattern.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs',
                     'Cpp2IL.Core/ISIL/Instruction.cs',
                     'Cpp2IL.Core/Analysis/CopyCoalescer.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64VirtualDispatch.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64ClassLayoutAbi.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64OverflowExceptionAbi.cs',
                     'Cpp2IL.Core/Utils/LegacyArm64ObjectIsInstAbi.cs',
                     'Cpp2IL.Core/Model/Contexts/MethodAnalysisContext.cs']
    changed = subprocess.check_output(['git', '-C', str(repo), 'diff', '--name-only', '-z', PIN]).decode().strip('\0').split('\0')
    untracked = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '--others', '--exclude-standard', '-z']).decode().strip('\0').split('\0')
    unsaved = sorted((set(changed + untracked) - {''}) - set(names))
    if len(names) != len(set(names)) or unsaved:
        raise ValueError('Incomplete/duplicate experimental patch file list; unsaved tool paths: ' + repr(unsaved))
    patch, files = [], []
    for name in names:
        original = subprocess.run(['git', '-C', str(repo), 'show', f'{PIN}:{name}'], capture_output=True)
        before = original.stdout.decode('utf-8') if original.returncode == 0 else ''
        after = (repo / name).read_text(encoding='utf-8')
        patch.append(f'diff --git a/{name} b/{name}\n')
        if not before:
            patch.append('new file mode 100644\n')
        patch.extend(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile='a/'+name if before else '/dev/null', tofile='b/'+name))
        files.append(dict(path=name, sha256=hashlib.sha256((repo/name).read_bytes()).hexdigest()))
    output = destination(ROOT, ROOT / f'src/re/tool-patches/cpp2il-sf2-hfa-experimental{suffix}.patch')
    output.write_text(''.join(patch), encoding='utf-8', newline='\n')
    report = dict(status='EXPERIMENTAL_SAVED_NOT_PROMOTED', upstream='https://github.com/SamboyCoding/Cpp2IL', commit=PIN,
                  source_inventory_coverage_verified=True, changed_or_new_tool_paths=len(set(changed + untracked)-{''}),
                  license='MIT', patch=str(output.relative_to(ROOT)), sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                  files=files, enable='Invoke-Cpp2IlMetadataRecovery.ps1 -RecoverHfa (records process-scoped CPP2IL_LEGACY_HFA=1)',
                  usage='Complete alternative patch against the pinned upstream, not an incremental patch to combine with the canonical one.',
                  scope='Experimental metadata-validated flat/nested HFA entry/call/result packing and value-type field addressing. '
                        'The class-macro recognizer additionally preserves scheduled scalar FP loads; '
                        'the bounded class-load witness also admits independent unsigned-offset 32-bit loads and rejects flag/finished W0 clobbers. '
                        'see native-fp-class-guard-caller and recovered-fp-class-guard reports. '
                        'Closed-generic layouts and nested scalar FP field paths preserve observed base-field '
                        'offsets and tail-padding reuse; unsupported layouts stay diagnostic. Analysis-warning '
                        'tails terminate by throwing so even unreachable tails cannot fall off a CIL method. '
                        'Surviving parameters bind to original signature positions even when earlier arguments are unused. '
                        'Type literal operands keep RuntimeTypeHandle when required by the exact expected parameter type, '
                        'instead of materializing System.Type before the native managed call. '
                        'Adjacent reference-type constructor fusion recognizes equivalent closed generic owner '
                        'contexts by canonical metadata definition/arguments, preserving receiver/block/order guards. '
                        'Existing public nonvirtual scalar/ref accessors restore foreign private field access only after exact native leaf proof. '
                        'A separate unique Assembly-only instance getter route requires no original/output owner initializer, '
                        'exact native field semantics and uncached attached output assembly/type/method/field identity at each read. '
                        'It preserves visibility flags, private stores and the existing public/static routes. '
                        'Exact complete two-word field-copy leaves recover managed whole-value assignment/return before generic ABI analysis. '
                        'Reviewed returning exception factories preserve their exact default constructor effect. '
                        'Exact value-this adjustors select independently bounded unboxed bodies and unique aliases while registered addresses stay intact. '
                        'Reviewed primitive boxing retains only proven initialized typed storage; address-taken and array liveness preserve original stores. '
                        'Exact FDE-bounded CFG witnesses recover cached metadata flags and cold initialization paths while preserving scheduled arithmetic; '
                        'the additive ordinary-method route requires an exact zR frame with empty FDE augmentation and retains the unchanged bounded matcher. '
                        'Unknown/exception-bearing frames are excluded from that new route; the pre-existing selected route still includes twelve zPLR bodies with unverified exception semantics. '
                        'typed legacy class initialization lowers to the existing CLR class-constructor contract rather than a no-op. '
                        'Reviewed raw class-init ABI captures require an unused result and exact metadata origin; known runtime helpers cannot acquire stale managed MethodInfo identities. '
                        'Class metadata Phi inputs require exact original type identity and edge-end definition availability, with topology, escape, cycle, 32-local and 256-visit bounds; constructor and reload order stay intact. '
                        'A pinned native caller/callee/constructor descriptor binds one reviewed indirect Enumerator return to its original stack buffer before SSA; '
                        'broader generic structure sizing and exception cleanup remain unresolved. '
                        'Native virtual dispatch carries an explicit receiver/target/slot proof through IR and emission; '
                        'Only the paired companion may follow at most 32 unique defining locals through available same-block copies; '
                        'function/class loads and original parameter receiver roots retain their existing guards. '
                        'unsupported native virtual candidates remain indirect, while original direct/base calls retain their dispatch. '
                        'This narrow reference-receiver, parameterless integer/reference-return witness does not recover general ABI widths, generic/interface/value-type dispatch or EH. '
                        'Exact image/FDE/body-pinned native Class::Init and overflow-factory ABI witnesses keep '
                        'their original X0 input/result and numeric diagnostics while removing false raw register inputs. '
                        'Boolean and base Exception result typing does not implement either native helper or its failure/cleanup behavior. '
                        'A separately pinned Object::IsInst signature retains original X0/X1 inputs and canonical Object result, '
                        'without semantic lowering, dynamic-class projection, COM removal or array-store fusion. '
                        'Canonical patch stays separate. Stack-spilled HFAs are explicit recovery failures; '
                        'integer multiword aggregates and general generic/indirect call recovery remain outside this experiment. '
                        'No clean-source or whole-ABI claim.')
    destination(ROOT, ROOT / f'reports/cpp2il-hfa-experimental-lock{suffix}.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(status=report['status'], files=len(files), sha256=report['sha256'])))


if __name__ == '__main__':
    main()
