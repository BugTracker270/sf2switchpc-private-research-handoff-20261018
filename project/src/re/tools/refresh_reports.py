"""Refresh factual progress from local artifacts; never reads key material."""
import collections
import datetime
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def read(path,default=None):
    path=ROOT/path
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else default
def write(path,text):destination(ROOT,ROOT/path).write_text(text,encoding='utf-8')
def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

TRIAGE={
'SciresM/hactool':('C; Windows CLI; PFS0/NCA/NSO','1.4.0 official Windows release executes successfully. Source clone pins current master separately. NCA header/body inspection, base-aware patch extraction and NSO decompression used. Key profile is local-only. It can return 0 after invalid headers, so semantic output gates are required.'),
'DarkMatterCore/nxdumptool':('C/C++; Switch hardware; content/tickets','rewrite branch reviewed as a format reference. Signature/ticket structures corroborated common-ticket parsing, including little-endian signature type. No console program installed; supplied NSPs suffice. No keys or SDK fetched.'),
'Adubbz/Ghidra-Switch-Loader':('Java; Ghidra extension; NSO/ARM64','Official 1.6.1-c600d05 release explicitly built for Ghidra 12.1.2, with published SHA-256 matched. Installed inside portable Ghidra. Real main import succeeded with ARM64 language and correct 0x7100000000 base.'),
'NationalSecurityAgency/ghidra':('Java plus native decompiler; Windows x64','Official Ghidra 12.1.2 release hash matched. Existing JDK 26 satisfies release minimum 21. Headless import, metadata labels and actual pseudocode/disassembly exports verified. Initial automatic analysis timed out at 600 seconds; bounded scripted recovery is used and recorded separately.'),
'Perfare/Il2CppDumper':('C#; Windows standalone; NSO + metadata','v6.7.46 runs on the actual effective NSO and metadata v24. 90,105 method records, metadata schemas, header and DummyDll generated. DummyDll bodies are stubs. Source confirms the <=24 static dummy-object argument rule used in independent ABI checks.'),
'SamboyCoding/Cpp2IL':('C#; .NET 10; NSO ARM64 to ISIL/CIL','Development commit built locally with installed SDK. NSO and ARM64 paths confirmed in source. Recovered CIL contains many diagnostic helper calls despite a 100% tool success message. A local MIT-source patch corrects legacy ARM64 static argument placement, verified on a native-matched sample. Full CIL correctness remains unproven.'),
'NepMods/Cpp2IL-Analysis':('C#; older specialized Cpp2IL fork','Source metadata and README reviewed. Stale rewrite/new-analysis instructions and inherited old release links do not establish better target support than current upstream. Not executed or imported. Reconsider only for a specific missing opcode after a native comparison.'),
'AssetRipper/AssetRipper':('C# / native Windows release; Unity serialized assets','Official 2.0.0 release digest matched; local headless web API bound to 127.0.0.1. Actual 2018.1.9f1 data loaded and exported. Folder-only backend detection is Unknown, so a separate staging copy with metadata-only DLLs aids field decoding. This synthetic Mono detection does not change original IL2CPP evidence.'),
'nesrak1/UABEA':('C#; Unity serialized data inspection','MIT upstream metadata reviewed; raw README fetch had transient transport failures. Deferred second-opinion inspector because primary export passed raw TextAsset equality checks. No unverified binary acquired; suitable only if a concrete serialized-data mismatch requires it.'),
'nesrak1/UABEANext':('C#; newer Unity inspector','MIT upstream identity/commit recorded. Documentation fetch failure preserved. Deferred; no assumption about current NSO or target-version support. Existing source-object manifest and raw files retain evidence for later inspection.'),
'djkaty/Il2CppInspector':('C#; legacy IL2CPP type/native tooling','AGPL upstream source metadata reviewed as a legacy reference. Not installed because working Dumper/current Cpp2IL/Ghidra paths exist. Do not infer modern ARM64 compatibility from historical capabilities.'),
'morluto/rea':('Node.js MCP/CLI; Ghidra provider','Official rea-agents 6.5.0 installed locally with npm lifecycle scripts disabled. Node 22.23.1 meets declared requirements. Doctor accepts Ghidra/JDK but Windows native self-test refuses removable exFAT TEMP: fixed NTFS is required. Host configuration was not edited; headless Ghidra fallback is functional.'),
'onerdna/sf-2.x-guide':('Markdown; Android-oriented engine guide','Describes transition to Unity/IL2CPP and tool workflow. Fundamental backend advice corroborates independently observed Switch data, but Android paths and later 2.x behavior are not transferred to Switch 1.1.0. No source license declared in metadata; reference-only, no code imported.'),
'moltinginstar/sf2mod':('Python/writeup; Android 2.46 save tooling','Android save/hash and signing-certificate/device-ID workflow is not a Switch save implementation. README reviewed; no mod, re-sign, cheat or device-injection commands run. Reference-only; no permission inferred to copy unspecified-license code or assets.'),
'onerdna/stalker':('Android application; mobile save viewer/modifier','GPL-3.0 source identity reviewed. Save record names can be compared only after matching the supplied Switch schemas. Mobile energy, Forge and signing assumptions are not used. No APK or intrusive Android helper installed.'),
'FlipThoseTitle/Gymnast-Tool-Suite':('Python; Blender 5.2+ / Cascadeur 2025.3+','Only source-only SF2 animation importer was fetched from the pinned GPL-3.0 tree. Its point-frame layout was independently matched to actual Switch animation data; an original bounded decoder was implemented. No bundled scenes or third-party Nekki assets fetched, and no Blender/Cascadeur add-on executed.'),
'NikkaGames/AutoShadow':('Android native instrumentation','Source identity/README only. Not a Switch dumper or port framework. No injection, executable mod or APK run; license metadata requires further review before any reuse.'),
'Unity-Technologies/InputSystem':('C# Unity package; future Windows input','Official package reference only. New current package cannot be assumed compatible with Unity 2018.1.9f1. Input implementation/editor migration is outside current reverse-engineering scope; no package added to a fake Unity project.')}

def main():
    now=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=3))).isoformat()
    lock=read('reports/toolchain-lock.json',{'repositories':[],'releases':[]})
    text=['# Repository/tool triage','',f'Updated {now} (Asia/Riyadh). Public source fetched without sending any game material.','']
    for item in lock['repositories']:
        repo=item['repository'].removeprefix('https://github.com/')
        platform,decision=TRIAGE.get(repo,('Unknown','Not reviewed'))
        slug=repo.replace('/','--');doc=ROOT/'reports'/'upstream'/(slug+'-README.md')
        if doc.exists():item.update(readme=str(doc),readme_sha256=digest(doc),status='REVIEWED_DOCS',review_note=decision)
        else:item['review_note']=decision
        text += [f'## {repo}','',f'- Authentic upstream: {item["repository"]}',f'- Pin: `{item.get("branch","unknown")}` / `{item.get("commit","unknown")}`',
            f'- License: {item.get("license","UNSPECIFIED")}; archived: {item.get("archived","unknown")}.',f'- Format/runtime: {platform}',f'- Target/version/use decision: {decision}','']
    releases=[]
    for name,relative,url,license,status,expected in [
      ('hactool 1.4.0','tools/hactool-1.4.0-win.zip','https://github.com/SciresM/hactool/releases/tag/1.4.0','ISC','EXECUTED_NCA_EXTRACTION',None),
      ('Ghidra 12.1.2','tools/ghidra_12.1.2_PUBLIC_20260605.zip','https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build','Apache-2.0','EXECUTED_NATIVE_IMPORT_DECOMPILE','b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d'),
      ('SwitchLoader 1.6.1-c600d05 / 12.1.2','tools/SwitchLoader-1.6.1-c600d05-Ghidra_12.1.2.zip','https://github.com/Adubbz/Ghidra-Switch-Loader/releases/tag/1.6.1-c600d05-Ghidra_12.1.2','ISC','REAL_NSO_IMPORT_VERIFIED','0bc6374c11cb7a1275a0eda22184b9b2efe5a9a7e415cc29361c334966c1f477'),
      ('Il2CppDumper 6.7.46','tools/Il2CppDumper-win-v6.7.46.zip','https://github.com/Perfare/Il2CppDumper/releases/tag/v6.7.46','MIT','EXECUTED_METADATA_RECONSTRUCTION',None),
      ('AssetRipper 2.0.0','tools/AssetRipper_win_x64-2.0.0.zip','https://github.com/AssetRipper/AssetRipper/releases/tag/2.0.0','GPL-3.0','ACTUAL_ASSETS_EXPORTED','9a7ef0e7c5c3ea5b90b4e6d855e2d98d5f7ec8c3f9e26fccbc194c6a7b01baf7')]:
        path=ROOT/relative
        if path.exists():
            sha=digest(path)
            if expected and sha!=expected:raise ValueError('Upstream release digest mismatch')
            releases.append(dict(name=name,source=url,local_path=str(path),sha256=sha,upstream_sha256=expected,
                integrity='MATCHED_PUBLISHED_DIGEST' if expected else 'LOCAL_HASH_ONLY_NO_UPSTREAM_DIGEST',license=license,status=status))
    lock.update(releases=releases,updated_at=now,
        rea=dict(version='6.5.0',status='BLOCKED_FIXED_NTFS_REQUIRED',package_lock='tools/rea-6.5.0/package-lock.json',host_config_changed=False),
        cpp2il=dict(commit='b5ad444b82267cb1e4b88b8b373c008105bdea52',framework='net10.0',patch='src/re/tool-patches/cpp2il-sf2-recovery-corrections.patch',
           patch_sha256=digest(ROOT/'src/re/tool-patches/cpp2il-sf2-recovery-corrections.patch'),corrections_lock='reports/cpp2il-corrections-lock.json',status='PARTIAL_RECOVERY_NATIVE_VALIDATION_REQUIRED'),
        ilspy=dict(version='11.1.0.9782',source='https://www.nuget.org/packages/ilspycmd/11.1.0.9782',license='MIT',status='PARTIAL_CSHARP_EXPORT_ERRORS_PRESERVED'))
    write('reports/toolchain-lock.json',json.dumps(lock,indent=2)+'\n');write('reports/repo-triage.md','\n'.join(text))
    source=read('analysis/assets/source-manifest-summary.json',{})
    content=read('analysis/assets/content-v2/content-summary.json',{})
    typed=read('analysis/assets/typed-components/summary.json',{})
    progress=read('analysis/nso/native-corpus/progress.json',{})
    library=read('analysis/nso/native-corpus-library/progress.json',{})
    corpus=read('analysis/nso/corpus-summary.json',{})
    sequential=read('analysis/assets/typed-components/sequential-summary.json',{})
    graph=read('analysis/assets/asset-graph-summary.json',{})
    types=read('analysis/il2cpp/ghidra-type-archive.json',{})
    audio=read('analysis/assets/audio-decoded/summary.json',{})
    registration=read('analysis/il2cpp/registration-integrity.json',{})
    mappings=read('reports/native-mapping-tests.json',{})
    leaves=read('reports/native-behavior-leaf-tests.json',{})
    ai=read('analysis/assets/ai-tables-v1/summary.json',{})
    native_ai=read('reports/native-ai-execution.json',{})
    reference_ai=read('logs/ai-reference-run.log',{})
    node=read('reports/native-node-integration.json',{})
    save_gate=read('reports/native-save-gate-execution.json',{})
    combat_types=read('analysis/nso/combat-layout-v2-type-application.json',{})
    combat_repairs=read('analysis/nso/combat-prototype-repairs-v2-type-application.json',{})
    geometry_types=read('analysis/nso/geometry-layout-v2-type-application.json',{})
    contact=read('reports/native-contact-geometry.json',{})
    capsule=read('reports/native-capsule-geometry.json',{})
    strike=read('reports/native-strike-selection.json',{})
    damage=read('reports/native-damage-combination.json',{})
    move_resolution=read('reports/move-template-resolution.json',{})
    empty_animation=read('reports/native-empty-animation-gate.json',{})
    bezier=read('reports/native-animation-bezier.json',{})
    animation_step=read('reports/native-animation-step.json',{})
    quest_graph=read('reports/quest-loading-graph.json',{})
    quest_lookup=read('reports/native-quest-lookup.json',{})
    currency=read('reports/native-currency-codec.json',{})
    currency_long=read('reports/native-currency-long.json',{})
    wallet=read('reports/native-wallet-arithmetic.json',{})
    native_regression=read('reports/native-regression.json',{})
    save_schema=read('reports/save-schema-research.json',{})
    save_scheduler=read('reports/native-save-scheduler.json',{})
    data_refs=read('analysis/nso/data-refs-summary.json',{})
    aggregate_abi=read('reports/arm64-currency-abi-gap.json',{})
    exception=read('reports/native-exception-boundary.json',{})
    array=read('reports/native-array-boundary.json',{})
    scoped_csharp=read('reports/scoped-csharp-type-audit.json',{})
    corrections=read('reports/cpp2il-corrections-lock.json',{})
    recovered_run=corrections.get('recovery_run','nso-stack-headers-v11')
    scalar=read('reports/native-scalar-accessors.json',{})
    scalar_direct=read(f'reports/recovered-scalars-{recovered_run}.json',{})
    scalar_isolated=read(f'reports/recovered-scalars-isolated-{recovered_run}.json',{})
    stack_audit=read(f'reports/cil-stack-audit-{recovered_run}.json',{})
    allocation_gap=read('reports/recovered-allocation-type-gap.json',{})
    allocation_identity=read(f'reports/recovered-allocation-identity-{recovered_run}.json',{})
    source_build=read(f'reports/recovered-source-build-{recovered_run}.json',{})
    source_project=read(f'reports/recovered-source-project-build-{recovered_run}.json',{})
    source_reference=read(f'reports/recovered-source-reference-check-{recovered_run}.json',{})
    source_legacy=read(f'reports/recovered-source-legacy-reference-check-{recovered_run}.json',{})
    source_profile=read(f'reports/recovered-source-profile-legacy-reference-check-{recovered_run}.json',{})
    profile_counts=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','unknown')}" for a in source_profile.get('assemblies',[]))
    auxiliary_resolved={name:read(f'reports/native-auxiliary-{name}-resolved-v1.json',{}) for name in ['sdk','subsdk0']}
    hfa_vector=read('reports/recovered-vector3-nso-hfa-v20d.json',{})
    boolean_recovery=read(f'reports/recovered-boolean-setter-{recovered_run}.json',{})
    better_source=read('reports/better-source-v1-compile.json',{})
    rust_probe=read('reports/rust-source-v4-validation.json',read('reports/rust-source-v1.json',{}))
    fp_class_guard=read('reports/recovered-fp-class-guard-nso-class-fp-loads-v21.json',{})
    fp_class_source=read('reports/recovered-source-profile-legacy-reference-check-nso-class-fp-loads-v21.json',{})
    generic_recovery=read('reports/generic-source-recovery-20261017.json',{})
    native_leaf_recovery=read('reports/native-leaf-source-recovery-20261017.json',{})
    value_this_box=read('reports/value-this-box-source-recovery-v30.json',{})
    cfg_initialization=read('reports/cfg-initialization-source-recovery-v31b.json',{}) or read('reports/cfg-initialization-source-recovery-v31.json',{})
    indirect_return=read('reports/indirect-return-source-recovery-v32.json',{})
    indirect_return_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in indirect_return.get('compiler_after',[])) or 'pending'
    class_guard_load=read('reports/class-guard-load-source-recovery-v33.json',{})
    class_guard_load_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in class_guard_load.get('compiler_after',[])) or 'pending'
    class_origin_phi=read('reports/class-origin-phi-source-recovery-v34.json',{})
    class_origin_phi_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in class_origin_phi.get('compiler_after',[])) or 'pending'
    plain_frame=read('reports/plain-frame-source-recovery-v35.json',{})
    plain_frame_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in plain_frame.get('compiler_after',[])) or 'pending'
    virtual_dispatch=read('reports/virtual-dispatch-source-recovery-v36.json',{})
    virtual_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in virtual_dispatch.get('compiler_after',[])) or 'pending'
    runtime_helper_abi=read('reports/runtime-helper-abi-source-recovery-v37.json',{})
    runtime_abi_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in runtime_helper_abi.get('compiler_after',[])) or 'pending'
    virtual_companion=read('reports/virtual-companion-source-recovery-v38.json',{})
    companion_compiler=', '.join(f'{name}: {total}' for name,total in virtual_companion.get('compiler_after',{}).items()) or 'pending'
    assembly_leaf=read('reports/assembly-leaf-getter-source-recovery-v39.json',{})
    assembly_leaf_compiler=', '.join(f"{name}: {row['after']}" for name,row in assembly_leaf.get('compiler',{}).items()) or 'pending'
    object_isinst=read('reports/object-isinst-abi-source-recovery-v40.json',{})
    object_isinst_compiler=', '.join(f"{name}: {row['after']}" for name,row in object_isinst.get('compiler',{}).items()) or 'pending'
    exception_regions=read('reports/exception-region-design-v36.json',{})
    runtime_class_layout=read('reports/class-layout-runtime-source-v37.json',{})
    class_layout_contract=read('reports/class-layout-translation-contract-v37.json',{})
    exception_parser=read('reports/exception-metadata-parser-v35.json',{})
    exception_review=read('reports/exception-metadata-independent-review-v35.json',{})
    native_exception_inventory=read('reports/class-guard-eh-eligibility-inventory-v35.json',{})
    enumerator_sret_assessment=read('reports/reference-enumerator-sret-assessment-v35.json',{})
    cfg_initialization_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in cfg_initialization.get('compiler_after',[])) or 'pending'
    value_this_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in value_this_box.get('compiler_after',[])) or 'pending'
    native_leaf_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in native_leaf_recovery.get('compiler_after',[])) or 'pending'
    generic_latest=generic_recovery.get('runs',[{}])[-1]
    generic_runtime=generic_latest.get('recovered_execution',{})
    generic_compiler=', '.join(f"{a['assembly']}: {a.get('unique_compiler_diagnostic_lines','pending')}" for a in generic_latest.get('compiler',[])) or 'pending'
    default_member=read(f'reports/recovered-default-member-{recovered_run}.json',{})
    class_guards=read(f'reports/recovered-class-guards-{recovered_run}.json',{})
    api_profile=read('reports/managed-api-profile.json',{})
    text_partition=read('reports/native-text-partition.json',{})
    source_sample=read(f'reports/scoped-source-build-{recovered_run}.json',{})
    native_quality=read('reports/native-pseudocode-quality.json',{})
    native_modules=read('reports/native-module-inventory.json',{})
    unwind_inventory=read('reports/native-unwind-inventory.json',{})
    unwind_recovery=read('reports/native-unwind-recovery.json',{})
    coverage=read('reports/analysis-coverage.json',{})
    # Old name-heuristic counters were initialized to zero, not measured
    # function-level coverage. Keep candidate totals but remove false precision.
    scoped_features={
        'combat':['reports/native-capsule-geometry.json','reports/native-strike-selection.json','reports/native-damage-combination.json'],
        'animation':['reports/native-animation-bezier.json','reports/native-animation-step.json'],
        'ai':['reports/ai-data-recovery.md','reports/native-ai-execution.json'],
        'story':['reports/quest-loading-graph.json','reports/native-quest-lookup.json'],
        'sparring':['reports/local-sparring.md'],
        'save':['reports/save-research.md','reports/native-save-gate-execution.json'],
        'economy_equipment':['reports/economy-research.md'],
        'input_platform':['reports/platform-dependency-matrix.csv'],
        'ui_localization':['reports/asset-integrity.md']}
    for name,feature in coverage.get('features',{}).items():
        for field in ['fully_understood','partially_inferred','not_analyzed']:feature.pop(field,None)
        feature['semantic_function_counts']='UNMEASURED; name candidates overlap and are not a coverage denominator'
        if name in scoped_features:feature.update(status='IN_PROGRESS',scoped_evidence=scoped_features[name])
    coverage.update(updated_at=now,native_corpus_progress=progress,native_functions_semantically_validated=2+leaves.get('passed',0),
        native_function_validation_count_method='Legacy static-only count of small functions; bounded execution is tracked by named reports and is not summed into a whole-function completion percentage.',
        validation_scope='Static ABI/layout checks plus bounded original ARM64 execution across documented function/slice scopes. Explicit wallet persistence stubs are separate from scopes with no game-function mocks. No original-runtime or complete subsystem parity certification.',
        raw_source_objects=source.get('total_objects'),raw_text_assets=source.get('text_assets'),exact_text_payload_matches=source.get('exact_text_payload_matches'),
        typed_component_results=typed,sequential_component_results=sequential,asset_graph_validation=graph,
        native_library_progress=library,indexed_native_corpus=corpus,parsed_ghidra_types=types.get('data_types'),
        audio_recovery=audio,native_registration_validation=registration,
        ai_table_schema=ai,bounded_native_ai_execution=native_ai,compiled_ai_reference=reference_ai,
        bounded_native_node_integration=node,bounded_native_save_gate=save_gate,
        bounded_native_capsule_geometry=capsule,bounded_native_strike_selection=strike,
        bounded_native_damage_slice=damage,move_template_resolution=move_resolution,bounded_native_empty_animation_gate=empty_animation,
        bounded_native_animation_bezier=bezier,bounded_native_animation_draw=animation_step,quest_loading_graph=quest_graph,bounded_native_quest_lookup=quest_lookup,
        bounded_native_currency_int=currency,bounded_native_currency_long=currency_long,bounded_native_wallet_arithmetic=wallet,native_regression=native_regression,
        default_save_schema=save_schema,bounded_native_save_scheduler=save_scheduler,
        indexed_native_data_references=data_refs,
        confirmed_currency_abi_recovery_gap=aggregate_abi,
        bounded_native_exception_boundary=exception,bounded_native_array_boundary=array,scoped_csharp_type_audit=scoped_csharp,
        bounded_native_scalar_accessors=scalar,recovered_scalar_direct=scalar_direct,recovered_scalar_isolated=scalar_isolated,
        recovered_stack_depth_headers=stack_audit,recovered_allocation_type_gap=allocation_gap,
        recovered_allocation_identity=allocation_identity,recovered_source_compilation=source_build,native_pseudocode_quality=native_quality,native_module_inventory=native_modules,
        recovered_source_project_compilation=source_project,recovered_source_reference_experiment=source_reference,scoped_source_compilation=source_sample,
        recovered_source_legacy_reference_experiment=source_legacy,managed_api_profile=api_profile,native_text_byte_partition=text_partition,
        recovered_source_profile_reference_experiment=source_profile,recovered_default_member_metadata=default_member,
        native_auxiliary_resolved=auxiliary_resolved,recovered_boolean_execution=boolean_recovery,
        experimental_hfa_vector_execution=hfa_vector,alternative_source_compilation=better_source,
        alternative_rust_probe=rust_probe,
        experimental_fp_class_guard=fp_class_guard,experimental_fp_class_source_compilation=fp_class_source,
        experimental_generic_source_recovery=generic_recovery,
        experimental_native_leaf_recovery=native_leaf_recovery,
        experimental_value_this_boxing=value_this_box,
        experimental_cfg_initialization=cfg_initialization,
        experimental_indirect_return=indirect_return,
        experimental_class_guard_load=class_guard_load,
        experimental_class_origin_phi=class_origin_phi,
        experimental_plain_frame=plain_frame,
        experimental_virtual_dispatch=virtual_dispatch,
        experimental_runtime_helper_abi=runtime_helper_abi,
        experimental_virtual_companion=virtual_companion,
        experimental_assembly_leaf_getter=assembly_leaf,
        experimental_object_isinst_abi=object_isinst,
        synthetic_exception_region_design=exception_regions,
        exact_common_runtime_class_layout=runtime_class_layout,
        bounded_class_layout_translation_contract=class_layout_contract,
        bounded_exception_metadata_parser=exception_parser,
        bounded_exception_metadata_review=exception_review,
        native_exception_inventory=native_exception_inventory,
        enumerator_sret_assessment=enumerator_sret_assessment,
        validated_unwind_ranges=unwind_inventory,unwind_range_export_progress=unwind_recovery,
        bounded_native_contact_geometry=contact,
        expanded_type_scopes=dict(combat=combat_types,combat_repairs=combat_repairs,geometry=geometry_types),
        custom_animation_count=len(content.get('animations',[])),
        full_reverse_engineering='NOT_COMPLETE')
    write('reports/analysis-coverage.json',json.dumps(coverage,indent=2)+'\n')
    md=f'''# Status — {now} (Asia/Riyadh)

Workspace: **F:\\SF2SwitchPC**, verified SanDisk USB, exFAT. Full clean decompilation usable for a later complete OS port is the primary goal; reverse engineering supports it. Platform port implementation is deferred. Acceptance gates: reports/decompilation-acceptance.json.

Latest complete source check: v40, {object_isinst_compiler}; both full builds fail. Current evidence status: {object_isinst.get('status','pending')}. Actual diagnostic helpers are bare returns, so unresolved calls can leave implicit default values; they provide neither recovered game behavior nor a runtime failure trap. Full clean source remains incomplete.

| Milestone | Verified status |
|---|---|
| M0 USB/preflight/infrastructure | Executed: local Git, guards/caches, hardware/tool inventory, source hashes, runnable parser tests. See boundary-tests.json, usb-preflight.json, usb-io.json and logs/. |
| M1 extraction/fingerprint | PASS: base and patch extracted/hashed with correct patch-aware effective view; Unity 2018.1.9f1, IL2CPP v24, ARM64 confirmed. |
| M2 symbols/assets | IN_PROGRESS: metadata, native corpus, raw/typed asset graph and scoped native checks produced. Full behavior coverage is not established. |
| M3–M7 Windows build/gameplay/performance | OUT_OF_SCOPE for this phase; not implemented or measured. |

Source NSP SHA-256:
- Base: `98d2d44f224321a174ce672826c5ece77d4f98350da336a21ffefc247e36cba5`
- Update: `21831c39c058b815d838a7543678685ef89e1e95778753e71091ae3b8415b8f8`

Decrypted CNMT: base title 0100AB000ABFE000 version 0; patch 0100AB000ABFE800 version 131072. Updated NACP: **1.1.0**. All 12 NCA filename IDs match content hashes; decrypted CNMT hashes match package contents. Original archives remain unchanged.

Confirmed artifacts:
- `unpacked/effective`: actual patch-aware executable/data view; 44 files. Per-file hashes/provenance: reports/extract-manifest.json.
- `analysis/il2cpp/effective-main`: Dumper type shells, 90,105 method records at 83,673 addresses, structure header and metadata mappings. These are **not original method bodies**.
- `analysis/il2cpp/research.sqlite`: searchable metadata/evidence corpus.
- `analysis/nso/SF2-effective.gpr`: real Ghidra ARM64 project. All 27,418 game-assembly targets have pseudocode/disassembly after 16 export errors were repaired. Additional library pass periodic progress: {library.get('completed_records','unknown')} / {library.get('total_targets','unknown')}. Latest searchable index: {corpus.get('unique_records','unknown')} unique records. Export coverage does not establish semantic understanding.
- Independently validated unwind inventory: {unwind_inventory.get('validated_records','pending')} nonoverlapping code ranges, with every managed metadata address at an exact range start. Current range exports: {unwind_recovery.get('ranges_with_pseudocode','pending')}; failed: {unwind_recovery.get('failed_ranges','pending')}; unattempted: {unwind_recovery.get('unattempted_ranges','pending')}. The initial snapshot identified 69,106 additional native ranges needing pseudocode. See reports/native-unwind-inventory.json and reports/native-unwind-recovery.json; range export does not establish full semantics.
- `analysis/il2cpp/sf2-arm64-types-layout-v2.gdt`: {types.get('data_types','unknown')} parsed Ghidra types, with independent runtime gates for static fields (0xB8), vtable (0x128) and array elements (0x20). The earlier stock runtime header is retained but superseded. Native ARM64 references to both registration structures are in analysis/nso/registration-xrefs.json.
- Expanded type recovery: {combat_types.get('methods_typed',0)+combat_repairs.get('methods_typed',0)} combat prototypes applied after repairing anonymous parameters, plus {geometry_types.get('methods_typed','pending')} geometry prototypes. All 2,853 combat methods re-exported; the 50 affected methods have a separate repair overlay.
- All {registration.get('metadata_unique_addresses','pending')} distinct metadata method addresses match native registration pointer tables; 39,378 metadata usage slots are within writable memory. This validates address membership, not every name alias or function behavior.
- `analysis/assets/unity-export`: AssetRipper export, including actual scenes, textures, fonts, audio and raw game data. No Windows Unity build exists.
- `analysis/assets/source-objects.jsonl`: {source.get('total_objects','unknown')} original serialized objects with byte offsets and hashes. **{source.get('exact_text_payload_matches','unknown')}/{source.get('text_assets','unknown')} TextAsset payloads match exports exactly.**
- `analysis/assets/content-v2`: {content.get('moves','pending')} move definitions, {content.get('templates','pending')} templates, {content.get('triggers','pending')} triggers, {len(content.get('animations',[]))} validated custom point-frame animations. Version 1 catalog misclassified two 60-frame binary headers as XML; v2 corrects this and retains original data.
- `analysis/assets/typed-components`: separate metadata-assisted staging copy; original backend remains IL2CPP. Clean sequential decoding produces {sequential.get('total','pending')} parseable component records and restores four initial errors. Original object/component identities are independently byte-checked. A header-only ScreenModel and GUISkin warning remain; JSON success alone is not complete layout proof.
- `analysis/assets/audio-decoded`: {audio.get('total','pending')} native FSB5 banks decoded with verified vgmstream; sample counts/channels/rates checked against bank metadata. Mixing, loop triggering and listening parity remain untested.
- `analysis/assets/ai-tables-v1`: {ai.get('totals',{}).get('archives','pending')} AI archives, {ai.get('totals',{}).get('blocks','pending')} blocks; all nested counts and payload boundaries checked against native reader schema. Includes distance/interframe pools and 531 node-shift animations. See reports/ai-data-recovery.md.
- `analysis/reconstruction/ai-reference`: compiled private functional evaluator; {reference_ai.get('boundaryChecks','pending')} extracted-data boundary checks. Bounded execution of original ARM64 functions: {native_ai.get('checks','pending')} comparisons, with initialization guards pre-set and no game-function mocks. This is not complete game execution.
- `analysis/reconstruction/physics-reference`: compiled node integration model compared with original ARM64 across {node.get('steps','pending')} node ticks and {node.get('bit_exact_float_checks','pending')} float-bit checks. Save hash gate: {save_gate.get('passed','pending')} bounded original-code checks, with no real save opened. Full collision, save schema and startup reachability still require analysis.
- Capsule geometry: {capsule.get('cases','pending')} cases / {capsule.get('checks','pending')} comparisons. Strike selection/list iteration: {strike.get('cases','pending')} cases / {strike.get('checks','pending')} comparisons. Damage combination slice: {damage.get('cases','pending')} comparisons with upstream factors supplied as inputs. Each report states exact synthetic metadata/allocator assumptions and original-code scope.
- `analysis/assets/moves-resolved-v1`: native-observed attribute/template order applied to {move_resolution.get('moves','pending')} moves. All 22 missing explicit filenames are explained by inherited files (7), physics (11), or no-animation flags (4); null/empty filename return path passes {empty_animation.get('checks','pending')} original-code checks. Event/interval candidates remain raw ordered definitions, not runtime parity.
- Original animation smoothing: {bezier.get('cases','pending')} Bezier cases / {bezier.get('checks','pending')} float-bit checks; actual sample application to current/previous model nodes: {animation_step.get('cases','pending')} cases / {animation_step.get('checks','pending')} checks. Full scheduling/interrupt/render parity remains unverified.
- `analysis/assets/quest-loading-v1`: native Include traversal reaches {quest_graph.get('initial_quest_definitions','pending')} initial definitions, including all {quest_graph.get('sensei_quest_definitions','pending')} Sensei quests. Potential action attachments reach {quest_graph.get('potential_quest_definitions','pending')} definitions across {quest_graph.get('potential_files','pending')} files. Name lookup/comparator: {quest_lookup.get('checks','pending')} original-code comparisons; global quest event/reward scheduling remains under investigation.
- Generic currency int codec/container: {currency.get('checks','pending')} checks; 64-bit Money/Bonus codec/getters: {currency_long.get('checks','pending')} checks. Wallet setter arithmetic: {wallet.get('checks','pending')} checks at explicit persistence/statistics boundaries. XML writes and imported pow remain outside that scope. See reports/economy-research.md.
- Latest bounded native regression: {native_regression.get('passed_scopes','pending')}/{native_regression.get('expected_scopes','pending')} scopes, {native_regression.get('checks','pending')} comparisons. Per-scope assumptions and exact logs are linked from reports/native-regression.json; this is not whole-game execution.
- Native runtime boundaries: {exception.get('checks','pending')} exception-pointer comparisons and {array.get('checks','pending')} array sizing/header/overflow comparisons. Allocation, type initialization and C++ throw boundaries are explicitly supplied; actual GC/unwinding remain unverified.
- Latest scoped C# type audit: {scoped_csharp.get('warning_total','pending')} ILSpy operand-type warnings in two exported classes. Array allocation recovery is corrected; helper-free CIL is not automatically valid source. See reports/scoped-csharp-type-audit.json.
- Recovered CIL stack/header audit: {stack_audit.get('status','pending')}. Invalid stack-flow or unresolved-allocation bodies are explicit diagnostic failures, not recovered game behavior. Eight scalar accessors have direct and isolated execution reports for {scalar.get('cases','pending')} original-code cases. Separate static-field allocation identity: {allocation_identity.get('status','unrepaired baseline')}; original failing evidence remains in reports/recovered-allocation-type-gap.json. A corrected identity does not certify complete initialization behavior.
- Complete game-assembly source compiler with compatible references: {source_profile.get('status','pending')}; diagnostic lines: {profile_counts}. Counts include cascades. See reports/recovered-source-profile-legacy-reference-check-{recovered_run}.json. Full source remains unready; no Unity/game build is implied.
- Preferred per-type source export preserves anonymous types and uses a verified legacy decompiler-resolution view. The marker-only view omits other original attributes and cannot be treated as a complete serialized Unity project. Earlier single-file/reference experiments are retained separately.
- Observed API assembly family: {api_profile.get('observed_api_family','pending')}, under IL2CPP. The official .NET 3.5 reference package is installed only as USB-hosted compiler metadata, with catalog SHA512 and NuGet signature/timestamp verification. Method-body errors remain distinct from reference-profile mismatches.
- Native-backed DefaultMember arguments recovered: {default_member.get('recovered_attributes','pending')}. A separate verified legacy decompiler-resolution view keeps game DLL bytes unchanged and resolves indexer/API contracts. Full body compiler status: {source_profile.get('status','pending')}; see reports/recovered-source-profile-legacy-reference-check-{recovered_run}.json. Both assemblies still fail with many body/type/inlining/call errors.
- Native class-init macro/CIL/source correlation: {class_guards.get('status','pending')}; see reports/recovered-class-guards-{recovered_run}.json. This scoped correction does not certify managed initialization ordering or complete method semantics.
- Actual recovered boolean getter/setter decisions: {boolean_recovery.get('status','pending')}; four original-code cases cover stored value, getter and initialization-call count. HFA experiment remains separate: Vector3 addition {hfa_vector.get('status','pending')} with {hfa_vector.get('checks','pending')} component checks. Caller packing, other aggregate shapes and complete source remain unverified.
- Alternative-tool comparison: reports/tool-survey-20261017.md. BetterCpp2IL unchanged scoped source compiler: {better_source.get('status','pending')}. Independent Rust recovery probe: {rust_probe.get('status','not run yet')}. Alternative counters are not source-completion measures.
- Earlier scheduled FP-load class macro experiment v21: {fp_class_guard.get('status','pending')}; original caller checks: {fp_class_guard.get('native_checks','pending')}. Its six unresolved generic component loads are addressed by the later opt-in generic-field experiment below. Canonical v19 remains separate.
- Generic-field/aggregate source corrections: {generic_recovery.get('status','pending')}. Latest recovered execution: {generic_runtime.get('status','pending')}, {generic_runtime.get('total_checks',generic_runtime.get('checks','pending'))} checks in its explicit isolated scope. Metadata/layout and sparse argument binding checks: {generic_recovery.get('metadata_checks','pending')}. Latest whole-source compiler diagnostic lines: {generic_compiler}. Counts include cascades; full clean source remains incomplete. See reports/generic-source-recovery-20261017.md.
- Native leaf/factory source corrections: {native_leaf_recovery.get('status','pending')}; run {native_leaf_recovery.get('recovery_run','pending')}. Current whole-source compiler diagnostic lines: {native_leaf_compiler}. Original private field flags stay intact; padding and full aggregate calls/runtime ordering remain separate. See reports/native-leaf-source-recovery-20261017.md.
- Value-receiver body selection and scalar boxing v30 baseline: {value_this_box.get('status','pending')}; compiler diagnostic lines {value_this_compiler}. Actual Int32 boxing passes its original-input expression tests; v30 InternalDecrypt has eight runtime initialization diagnostics and zero execution cases. Diagnostic growth is documented in reports/v30-diagnostic-delta-analysis.json. See reports/value-this-box-source-recovery-v30.md.
- Bounded CFG initialization and static getter recovery: {cfg_initialization.get('status','pending')}; run {cfg_initialization.get('recovery_run','pending')}; compiler diagnostic lines {cfg_initialization_compiler}. Recovered game-code execution and CLR class-constructor-contract checks have separate scopes. See reports/cfg-initialization-source-recovery-v31b.md and reports/cfg-initialization-source-recovery-v31.md (failed baseline).
- Reviewed indirect enumerator return and runtime-initializer recovery: {indirect_return.get('status','pending')}; run {indirect_return.get('recovery_run','pending')}; compiler diagnostic lines {indirect_return_compiler}. Actual recovered iteration fragments, original ARM64 witnesses and guard fixtures have separate scopes. General aggregate ABI, complete SetStage exception handling and full clean source remain incomplete. See reports/indirect-return-source-recovery-v32.md.
- Scheduled class-guard input loads: {class_guard_load.get('status','pending')}; run {class_guard_load.get('recovery_run','pending')}; compiler diagnostic lines {class_guard_load_compiler}. The unchanged recovered boolean reader passes 811 original-native return cases and 3244 checks with actual CLR calls; native tests use initialized runtime state. The 289 additional static matcher candidates do not certify 289 recovered methods. Alternate-entry/cold guards, class provenance and complete source remain incomplete. See reports/class-guard-load-source-recovery-v33.md.
- Edge-aware class metadata identity: {class_origin_phi.get('status','pending')}; run {class_origin_phi.get('recovery_run','pending')}; compiler diagnostic lines {class_origin_phi_compiler}. Six sampled initialization requests lower correctly; actual GetSafe CIL retains three constructor requests and subsequent field reloads. Guards, current regressions and CIL correlation have separate scopes; GetSafe is not executed as a whole. See reports/class-origin-phi-source-recovery-v34.md.
- Ordinary exact plain-frame recovery: {plain_frame.get('status','pending')}; run {plain_frame.get('recovery_run','pending')}; compiler diagnostic lines {plain_frame_compiler}. The new ordinary scope requires an exact zR frame with empty augmentation and preserves the existing bounded CFG matcher. The older selected route retains twelve zPLR bodies with unverified exception semantics. See reports/plain-frame-source-recovery-v35.md.
- Native virtual dispatch recovery: {virtual_dispatch.get('status','pending')}; run nso-virtual-dispatch-v36; compiler diagnostic lines {virtual_compiler}. Two actual Stream.ReadByte sites now emit callvirt; the prefix still contains a live unresolved MethodInfo load, so actual prefix runtime execution remains false. Unsupported virtual candidates retain diagnostics. See reports/virtual-dispatch-source-recovery-v36.md.
- Native runtime-helper ABI recovery: {runtime_helper_abi.get('status','pending')}; run nso-runtime-helper-abi-v37; compiler diagnostic lines {runtime_abi_compiler}. Correct one-X0 signatures remove phantom method-metadata dependencies while retaining numeric helper diagnostics. The unchanged inspector finds a clean two-callvirt reader prefix; its separate isolated clone of 47 original instructions passes 802 native cases / 7,218 comparisons. Whole Read execution remains zero and both complete source builds still fail. See reports/runtime-helper-abi-source-recovery-v37.md.
- Paired virtual companion copies: {virtual_companion.get('status','pending')}; run nso-virtual-companion-copy-v38; compiler diagnostic lines {companion_compiler}. The unchanged complete XmlExtensions.TryGetAttribute helper passes 26 host XML cases / 104 comparisons with five observed virtual getter calls. Native XML parity and full game execution remain unproved. Both complete source builds fail. See reports/virtual-companion-source-recovery-v38.json.
- Same-assembly native getter recovery: {assembly_leaf.get('status','pending')}; run nso-assembly-leaf-getter-v39; compiler diagnostic lines {assembly_leaf_compiler}. Private field visibility stays intact; 99 Serializer reads use its existing internal property. Native, contract, production and fresh-output checks pass in their stated scopes. Six added compiler diagnostics expose prior unchanged invalid arithmetic/casts and remain unresolved. Both complete source builds fail. See reports/assembly-leaf-getter-source-recovery-v39.json.
- Exact Object::IsInst ABI: {object_isinst.get('status','pending')}; run nso-object-isinst-abi-v40; compiler diagnostic lines {object_isinst_compiler}. Original X0/X1 inputs and nominal Object result pass signature/IR checks. Actual emitted helper/class-input semantics remain missing: the injected diagnostic helper is a bare return and sampled results can read as implicit null. Five sampled Array bodies remain default stubs. See reports/object-isinst-abi-source-recovery-v40.json and reports/diagnostic-scaffolds-nso-object-isinst-abi-v40.json.
- Exception-region foundation: {exception_regions.get('status','pending')}. The standalone synthetic region validator and independent CFG/clone checks do not implement production EH, handler roots or exception-entry SSA. See reports/exception-region-design-v36.md.
- Exact common runtime source: {runtime_class_layout.get('status','pending')}. B04F60 is bool Class::Init(Il2CppClass*), with one class input, metadata-layout effects and native cleanup; it is separate from managed .cctor. The bounded Byte[] host metadata contract remains unimplemented. See reports/class-layout-runtime-source-v37.md and reports/class-layout-translation-contract-v37.md.
- Bounded exception-metadata parser: {exception_parser.get('status','pending')}; synthetic tests {exception_parser.get('synthetic_tests','pending')}; independent checks {exception_review.get('checks','pending')}. Original LSDA/actions/type references and CFI instruction observations are reproduced. This does not emit handlers, finalize unwind rows or execute unwinding. See reports/exception-metadata-parser-v35.md.
- Confirmed exception-recovery gap: all 44 inspected v33 DLLs contain zero CIL exception regions, while the original UnloadDependencies LSDA has three landing entries. Native zPLR/personality frames are excluded from proposed ordinary CFG normalization. The reference-enumerator census finds no additional game caller satisfying the conservative exception-free, receiver-only contract. These read-only findings do not add production recoveries. See reports/class-guard-eh-eligibility-inventory-v35.json and reports/reference-enumerator-sret-assessment-v35.md.
- Original main text-byte partition: {text_partition.get('status','pending')}. Validated frames, PLT and residual words are accounted for separately; zero/NOP observations are not proof that residual bytes can be discarded. See reports/native-text-partition.json.
- Native pseudocode quality snapshot: {native_quality.get('status','pending')}. Partial-output warnings and out-of-frame listing instructions are separate from export success. See reports/native-pseudocode-quality.json. All four modules now have complete validated-range exports: main 152904, SDK 24032, subsdk0 9774, rtld 23. The SDK timeout is preserved alongside its successful retry. Auxiliary corpora remain separate from main; residual text and semantics are still under review.
- Save scheduling: {save_scheduler.get('checks','pending')} comparisons using supplied Unity clock and original base writers. Strict >60-second reset, four-request timer budget and forced dispatch are verified within that scope. Default save structure and original data:/userdata paths are mapped; complete schema/durable IO remain unfinished.
- Native data-reference index: {data_refs.get('references','pending')} adjacent ARM64 ADRP/LDR witnesses to {data_refs.get('distinct_slots','pending')} known metadata/string slots across {data_refs.get('functions_scanned','pending')} functions. This is a bounded static cross-reference method, not full dataflow or reachability coverage.
- `reports/local-sparring.md` and `reports/save-research.md`: native two-player input/fight flow and four serialized save-slot bindings (0–3). `reports/platform-dependency-matrix.csv` records observed adapters and required replacement tests.

Verification and limitations:
- Runnable tests: `python -m unittest discover -s tests -v`; USB boundary tests: `src/tools/Test-UsbWriteBoundary.ps1`. Exact results under logs/ and reports/.
- {mappings.get('passed',0)} mapping/ABI checks and {leaves.get('passed',0)} small control-flow checks passed. Four small native functions have scoped static validation; complete subsystem behavior remains unverified.
- Baseline Cpp2IL reported 37,996/37,996 success, but helper/diagnostic calls remain in many bodies. ILSpy exports include exact errors and partial methods. Recovered CIL/C# is a hypothesis requiring native correction.
- Ghidra initial automatic analysis timed out at 600 seconds; bounded explicit function exports continue. Metadata labels/address placement are distinct from verified gameplay semantics.
- REA 6.5.0 installed on USB, but its Windows native self-test requires fixed NTFS and refuses this removable exFAT volume. Headless Ghidra fallback works. No host agent configuration edited.
- Startup native code requests 60 FPS; FixedUpdate drives custom per-tick physics and a reduced-FPS compensation path. Further combat-clock/replay validation remains. **No actual gameplay FPS or 120-FPS result is claimed.**
- Residual mobile raid/Forge/social code/data is present; runtime availability on Switch is not inferred from its presence.
- No playable original reference was supplied for runtime parity tests. This does not prevent continuing static analysis, but runtime timing/behavior equivalence cannot be certified from recordings that do not exist.

Last confirmed outputs are the manifests/indexes above; exact commands and return codes are saved in logs/. Metadata-linked pseudocode export is complete. Primary remaining work is buildable source recovery: unresolved helpers, diagnostic bodies, operand/call ABI/control-flow/type correctness, complete native/module coverage and explicit runtime/platform contracts. Supporting behavioral comparisons do not replace source compilation and completeness gates.

**Full decompilation and semantic reverse engineering: NOT COMPLETE. No playable Windows executable has been built.**
'''
    write('STATUS.md',md)
    write('TASKS.md',f'''# Task ledger

- PASS: USB identity/boundary, local workspace/repository, original hashes and PFS0/NCA inventory.
- PASS M1: base/update extraction and verified engine/version fingerprint.
- IN_PROGRESS M2: native pseudocode, symbols, typed asset/dependency catalogs and method traces.
- PASS RANGE EXPORT ONLY: all 152,904 independently validated main exception-frame ranges have pseudocode/disassembly, with zero recorded export failures. Native quality, residual text and auxiliary modules remain under review; range coverage does not establish clean source.
- PASS: raw equality for all 2,664 TextAsset payloads and custom animation format validation.
- PASS: native-schema accounting for all 1,578 compressed AI archives / 6,084 blocks and compiled/native function comparisons. Full AI policy remains IN_PROGRESS.
- PASS SCOPED: compiled node/slow-mode integration versus original ARM64 and disabled save-hash gate. Full collision and save/startup semantics remain IN_PROGRESS.
- PASS SCOPED: capsule geometry, first-contact selection, damage arithmetic slice and empty animation-file branch; full combat remains IN_PROGRESS.
- STATIC NATIVE SCHEMA APPLIED: all 932 move template/attribute orders; 22 non-explicit filenames explained and six original missing-template references retained.
- PASS SCOPED: 32/64-bit currency codecs and complete Money/Bonus getters. Wallet arithmetic matches compiled references at explicit persistence/statistics boundaries; full economy and XML transactions remain IN_PROGRESS.
- STATIC TRACED: serialized Sparring callback reaches mode 2/module 8; logical save slots are XML records with a shared users.xml/backup path. Scheduling, schema and failure handling continue.
- PARTIAL: Cpp2IL recovered CIL/C#; diagnostic helpers and ILSpy failures retained.
- PRIMARY ACCEPTANCE: full clean recovered logic must compile and support a later complete OS port. Native pseudocode/metadata coverage, diagnostic throw bodies and unresolved helpers do not satisfy this gate. See reports/decompilation-acceptance.json.
- PASS SCOPED: original exception-pointer transport and array size/header/overflow flow at explicit runtime boundaries. Native GC, allocation failures, stack capture and exception unwinding remain IN_PROGRESS.
- CORRECTED TOOL RECOVERY: strict legacy array-allocation recognition, conservative exception-helper classification and boolean/integer/array-length propagation. Remaining ILSpy type warnings and aggregate ABI gaps are explicit.
- PASS SCOPED: eight recovered scalar accessors versus 768 original ARM64 cases in direct and isolated CIL execution. The v11 static allocation identity failure is retained; v13 preserves VersionContainer using explicit separate allocation without an extra instance constructor. Full initialization and source-build correctness remain IN_PROGRESS.
- STACK RECOVERY: headers are computed per method and unbalanced bodies become explicit diagnostic failures. Stack depth/header checks do not certify operand types or semantic completeness.
- CONFIRMED TOOL GAP: 16-byte currency arguments/results span two native integer registers; the current managed ARM64 resolver represents one. Native witnesses and candidate counts are in reports/arm64-currency-abi-gap.json. Multiword argument/return recovery remains IN_PROGRESS.
- EXPERIMENTAL SOURCE RECOVERY: generic field paths, nested FP aggregates, terminating diagnostic tails and sparse parameter typing. Latest evidence: reports/generic-source-recovery-20261017.md; status {generic_recovery.get('status','pending')}. Continue whole-source and native-backed call/type/control-flow correction; successful scoped execution is not a full build.
- EXPERIMENTAL NATIVE LEAF RECOVERY: {native_leaf_recovery.get('status','pending')}; current compiler diagnostic lines {native_leaf_compiler}. See reports/native-leaf-source-recovery-20261017.md. Field visibility, exact scalar accessor bodies, whole-field integer copies and constructor effects have separate gates; full source remains incomplete.
- EXPERIMENTAL VALUE-THIS/BOXING: {value_this_box.get('status','pending')}; compiler diagnostic lines {value_this_compiler}. Resolve exact CFG metadata/class initialization guards next; retain semantic cold branches and audit increased diagnostics. No full codec or source-build success.
- EXPERIMENTAL CFG INITIALIZATION: {cfg_initialization.get('status','pending')}; compiler diagnostic lines {cfg_initialization_compiler}. Preserve static constructor effects and metadata-origin proof; actual recovered method execution is a separate gate. Full clean source remains incomplete.
- EXPERIMENTAL INDIRECT RETURN/INITIALIZERS: {indirect_return.get('status','pending')}; compiler diagnostic lines {indirect_return_compiler}. Reviewed return-buffer identity is checked through actual recovered CIL without default insertion or local retargeting. General aggregate ABI, exception semantics and complete source still require recovery. See reports/indirect-return-source-recovery-v32.md.
- EXPERIMENTAL SCHEDULED CLASS GUARDS: {class_guard_load.get('status','pending')}; compiler diagnostic lines {class_guard_load_compiler}. Retain real constructor requests and scheduled field reads. Direct boolean-reader recovery passes its 811 native return cases; cold/alternate-entry CFG shapes and ambiguous class origins remain. See reports/class-guard-load-source-recovery-v33.md.
- EXPERIMENTAL CLASS ORIGIN PHI: {class_origin_phi.get('status','pending')}; compiler diagnostic lines {class_origin_phi_compiler}. Require identical original class identity on every predecessor edge, bounded proof work and preserved constructor/reload ordering. Actual CIL correlation does not certify complete caller execution. See reports/class-origin-phi-source-recovery-v34.md.
- EXPERIMENTAL ORDINARY PLAIN FRAMES: {plain_frame.get('status','pending')}; compiler diagnostic lines {plain_frame_compiler}. Require exact plain zR boundaries before the existing ordinary CFG normalization. New EH-bearing bodies remain excluded; native exception edges, cleanup and the twelve legacy selected zPLR bodies still require recovery. See reports/plain-frame-source-recovery-v35.md.
- EXPERIMENTAL VIRTUAL DISPATCH: {virtual_dispatch.get('status','pending')}; compiler diagnostic lines {virtual_compiler}. Preserve verified callvirt versus original direct calls; recover live method-metadata loads and unsupported signatures before claiming full method execution. See reports/virtual-dispatch-source-recovery-v36.md.
- EXPERIMENTAL NATIVE HELPER ABI: {runtime_helper_abi.get('status','pending')}; compiler diagnostic lines {runtime_abi_compiler}. Preserve exact image/body/frame/alias guards and unresolved helper effects. Recover helper semantics and broader virtual shapes; the cloned prefix comparison across 802 cases is separate from the complete Read method or game execution. See reports/runtime-helper-abi-source-recovery-v37.md.
- EXPERIMENTAL VIRTUAL COMPANION COPIES: {virtual_companion.get('status','pending')}; compiler diagnostic lines {companion_compiler}. Preserve exact target/root/purity/escape contracts. One complete unchanged XML helper passes a host-framework runtime test; producer roots, general signatures, helper effects and production EH remain unresolved. See reports/virtual-companion-source-recovery-v38.json.
- EXPERIMENTAL SAME-ASSEMBLY GETTERS: {assembly_leaf.get('status','pending')}; compiler diagnostic lines {assembly_leaf_compiler}. Preserve attached assembly/member identity, original visibility and exact native leaf proof. Two private constructor stores and six newly exposed prior arithmetic/cast errors remain unresolved; complete source still fails. See reports/assembly-leaf-getter-source-recovery-v39.json.
- EXPERIMENTAL OBJECT::ISINST ABI: {object_isinst.get('status','pending')}; compiler diagnostic lines {object_isinst_compiler}. Recover actual class provenance, assignability and result semantics; numeric calls into a bare-ret diagnostic helper are placeholders. Original fault/metadata/COM ordering and production exception handling still require recovery. The complete source and no-placeholder acceptance gates remain failed. See reports/object-isinst-abi-source-recovery-v40.json.
- CLASS-LAYOUT RUNTIME BOUNDARY: preserve the verified Boolean result, one-class ABI, metadata effects and cleanup of Class::Init. Keep managed .cctor separate; the exact Byte[] host metadata proposal has no production implementation. See reports/class-layout-translation-contract-v37.md.
- EXCEPTION METADATA FOUNDATION: {exception_parser.get('status','pending')}; independent review {exception_review.get('status','pending')}. Retain malformed/unknown rejection and explicit indirect type entries. Add actual exception-region/handler/SSA/emission contracts before claiming cleanup recovery; CFI observations are not finalized unwind rows. See reports/unload-exception-recovery-proposal-v35.md.
- CONFIRMED EH GAP: original cleanup/landing paths are absent from the inspected recovered CIL exception tables. Restore exception semantics before claiming clean portable source; do not simplify exception-bearing frames or generalize enumerator storage from normal-flow liveness alone.
- BLOCKED TOOL ONLY: REA Windows native authority requires fixed NTFS; headless Ghidra fallback is active.
- NOT_COMPLETE: complete feature/system semantic understanding and original-runtime validation.
- OUT_OF_SCOPE: Windows implementation, Unity migration, gameplay build and FPS certification until user's next task.
''')
    extra=read('reports/vgmstream-lock.json',{})
    if extra:
        lock['additional_tools']=[extra]
    unicorn=read('reports/unicorn-lock.json',{})
    if unicorn:lock.setdefault('additional_tools',[]).append(unicorn)
    corrections=read('reports/cpp2il-corrections-lock.json',{})
    if corrections:lock['cpp2il']['complete_corrections']=corrections
    legacy_references=read('reports/legacy-reference-assemblies-lock.json',{})
    if legacy_references:lock.setdefault('additional_tools',[]).append(legacy_references)
    for tool_report in ['reports/il2cpp-dumper-rs-source-lock.json','reports/il2cpp-dumper-rs-dependencies-lock.json','reports/better-source-v1.json','reports/cpp2il-hfa-experimental-lock.json','reports/rust-nso-mapping-patch-lock.json','reports/rust-source-v4-mapping.json','reports/rust-source-v4-validation.json']:
        if (ROOT/tool_report).exists():
            lock.setdefault('experimental_tool_evidence',[]).append(dict(report=tool_report,sha256=digest(ROOT/tool_report)))
    metadata_patch=ROOT/'src/re/tool-patches/cpp2il-nso-metadata-addresses.patch'
    if metadata_patch.exists():lock['cpp2il'].update(metadata_patch=str(metadata_patch.relative_to(ROOT)),metadata_patch_sha256=digest(metadata_patch))
    write('reports/toolchain-lock.json',json.dumps(lock,indent=2)+'\n')
    print('Reports/status refreshed',now)

if __name__=='__main__':main()
