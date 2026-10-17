# Decompilation quality and unresolved work

Updated 2026-10-17T08:26:34.003364+00:00. Full clean decompilation suitable for a later complete OS port is the primary goal and is **NOT COMPLETE**. Reverse engineering supports this goal. Acceptance gates: reports/decompilation-acceptance.json.

Native corpus: 152914 records; statuses {'PSEUDOCODE_EXPORTED': 152914}. This includes 69241 explicitly identified native registration/runtime helpers in addition to 83,673 distinct metadata-linked addresses. All metadata addresses independently match registered native method/generic pointer tables.

All 83,673 distinct metadata-linked addresses now have native pseudocode exports, plus 69241 explicitly identified registration/runtime helpers. The last failing regex method at 0x700970 was repaired by independently validating three signed-relative switch tables: all 176 guarded indices were executed in original ARM64. Ghidra body coverage grew from 9,400 to 46,880 bytes and the subsequent export succeeded. See analysis/nso/regex-switch-repair.json and native-regex-switch-repair-v1. This does not prove regex semantics or comprehensively decompile native engine functions outside the selected address sets.

The NSO's MOD0-linked exception table provides a separate inventory: 152,904 FDE/CIE ranges validate with no overlaps, and all 83,673 managed metadata addresses match exact starts. The initial corpus had no pseudocode at 69,106 other range starts. Native-engine recovery now uses these proven bounds; current progress is reports/native-unwind-recovery.json. These ranges cover 36,292,460 of 37,181,704 text bytes. Remaining text includes material outside this inventory and must be classified separately; neither range membership nor pseudocode proves semantics. The decoder follows the primary LSB exception-header encoding specification and checks the pinned LLVM 18.1.8 parser's FDE/CIE conventions. References are recorded in reports/native-unwind-inventory.json.

Scoped type application: 11 methods, 27 metadata slots; 0 recorded type errors. Exact report: analysis/nso/scoped-type-application.json. The Hit layout gate matches the known native damage offset `0x1C`.

That line describes the latest application pass. Additional preserved scope reports cover all 2,853 combat methods, the 50 anonymous-parameter repairs, the 224 behavior/AI targets and 102 geometry methods. Original partial errors and successful repair overlays are retained separately. See expanded_type_scopes in the JSON report.

Measured recovered-CIL comparison after correcting the legacy virtual-table offset and recovering stripped allocation/class-initialization helpers:

[
  {
    "assembly": "Assembly-CSharp.dll",
    "bodies": 17718,
    "previous_helper_methods": 10180,
    "current_helper_methods": 5829,
    "current_diagnostic_methods": 5705,
    "helper_method_reduction": 4351,
    "stack_rejection_diagnostic_methods": 247
  },
  {
    "assembly": "Assembly-CSharp-firstpass.dll",
    "bodies": 10401,
    "previous_helper_methods": 6328,
    "current_helper_methods": 4513,
    "current_diagnostic_methods": 4637,
    "helper_method_reduction": 1815,
    "stack_rejection_diagnostic_methods": 326
  }
]

Many diagnostic/helper bodies remain. Earlier whole-project ILSpy exports under analysis/il2cpp/cpp2il-csharp-nso-metadata are partial and have per-assembly exit code **70**. The preserved v4 TacticalTableHolder/Vector2f exports retain correct BinaryReader targets. Latest nso-bool-fields-v19 VersionContainer/Triangle exports retain 113 operand-type warnings. An exported helper-free body can still be invalid. See reports/scoped-csharp-type-audit.json. The opcode/operand CIL audit is syntactic and does not verify stack types or semantic behavior.

The two game assemblies have 6,140 fewer helper-bearing methods than the legacy-vtable pass. This is a syntax/recovery metric, not semantic proof; rejecting unsafe inferred exception helpers can increase unresolved calls, and rejected bodies can reduce helper counts. The correction harness now passes 211 checks, including four synthetic allocation-emission checks. All 44 latest assemblies have zero malformed bodies under the limited syntax audit. Complete single-file C# compiler experiment status: pending. Per-type project export/compiler status: pending. Its .NET 10 reference environment is diagnostic and is not a Unity/game build. Declaration/reference errors can prevent later method-body diagnostics from appearing; low diagnostic counts do not establish closeness to clean source.

The scoped Credentials/AuthenticationTypes source experiment is pending. This compiles the unchanged two-type ILSpy output without recovered dependency DLLs or replacement bodies. It is a small library-data source sample, not recovered playable combat. The source marker-only view preserves a whitelist of metadata-listed markers but omits other original attributes, including serialization-relevant contracts; the tool-annotated view and original metadata remain separate evidence. The omitted metadata is a required recovery task, so this view is not a complete Unity source project.

Observed mscorlib/System assembly identities are 2.0 and System.Core is 3.5, copied from original metadata by the pinned Dumper. The runtime backend remains IL2CPP. Official Microsoft .NET 3.5 reference metadata, verified by published catalog SHA512 and NuGet package signature/timestamp, enables a closer compiler context without installing a host framework. Compatible-reference compiler results are in reports/recovered-source-legacy-reference-check-nso-bool-fields-v19.json: status pending. This check reaches body errors in main while firstpass can still stop at declaration errors. Diagnostic counts include cascades and do not count independent fixes.

Native-backed DefaultMember restoration is PASS_NATIVE_ARGUMENT_METADATA_AND_INDEXER_SOURCE_CORRELATION, with 116 emitted arguments decoded and matched to actual metadata properties. A strict cache-generator shape and constructor identity, three-family/shared-string-wrapper consensus, and an independently executed native UTF8/constructor path support this restoration. The ListWrapper project output now renders a real indexer. Other attribute arguments remain incomplete.

A separate decompiler input view preserves game DLL bytes and substitutes only matching framework metadata with official unstripped legacy references. This resolves standard-library accessor/name contracts and preserves anonymous-type definitions during project export. Its actual compatible-reference body compiler results are SOURCE_BUILD_LIMITATIONS_CONFIRMED; see reports/recovered-source-profile-legacy-reference-check-nso-bool-fields-v19.json. Both assemblies still fail with many invalid casts, arithmetic, visibility, missing-member and call errors. These are compiler observations, often cascaded, not counts of independent source fixes or a completion percentage.

The v10 stack audit found 35,384 understated MaxStack headers, 1,018 stack-flow failures and 44 injected helper types with no base. Headers had been left at zero while automatic computation was disabled. The generator now computes each header inside the per-method error boundary, rejects invalid stack flow explicitly and gives its injected helper a System.Object base. Latest stack audit status: PASS_STACK_DEPTH_AND_HEADERS_ONLY, understated headers 0, stack-flow failures 0, helper types without a base 0. The syntax audit records 999 stack-rejection diagnostic bodies; they deliberately throw a recovery error and are not original behavior. A valid stack depth does not establish valid operand types.

Eight original native scalar accessors produce 768 cases / 1,760 checks, including bounds errors through the original exception factory and supplied runtime boundaries. Direct recovered-type execution status is PASS_RECOVERED_SCALARS_VS_ORIGINAL_NATIVE_FIXTURES (0 failures in 768 attempted cases); static initialization remains part of that test. Isolated recovered accessor status is PASS_RECOVERED_SCALARS_VS_ORIGINAL_NATIVE_FIXTURES (0 failures in 768 cases). Isolation replaces the one field load with an int-array argument and remaps metadata tokens; it retains all other instruction/branch bytes, local types and original stack limits. Its own reference getter/setter/bounds checks run first. This separation does not certify constructors or the recovered class as a whole.

The preserved v11 static identity witness fails: VersionContainer.Zero was System.Object although native allocation receives VersionContainer_TypeInfo. The emitter fused a later base constructor into allocation. The repair fuses only an adjacent same-type constructor within one block; other known reference types use explicit zeroed allocation with later initialization/calls retained. Latest independent static identity status: PASS_STATIC_ALLOCATION_IDENTITY_ONLY. Four synthetic emitted-CIL checks verify exact reference type, zeroed fields, no implicit instance constructor, and one explicit later constructor call. Complete class initialization and portable source semantics remain unverified. The original failure remains in reports/recovered-allocation-type-gap.json; new identity results are in reports/recovered-allocation-identity-nso-bool-fields-v19.json.

Native-output quality is audited independently from exporter success: RECOVERY_QUALITY_LIMITATIONS_CONFIRMED, snapshot {'records': 152914, 'records_with_frame': 152904, 'records_with_partial_output_markers': 90808, 'records_with_listing_outside_frame': 5963}. Warning markers include indirect flow and are not all independent defects. Listing addresses outside FDE bounds require explicit flow/boundary review; no automatic truncation is treated as a repair. Newly exported range records also retain decompiler messages and outside-frame byte counts.

Native exception/helper work: the actual raiser at 0xB4C880 is identified by its preserved incoming exception pointer, trace_ips access, eight-byte C++ exception wrapper and native throw tail, with three independent corlib method families agreeing. Thirty-two cases / 224 original-code comparisons reach explicitly supplied C++ allocation/throw boundaries; real unwinding and stack capture remain untested. Initial v5/v6 recovery aborted with Out of memory during full-text thunk decoding. The legacy NSO scanner now indexes fixed-width B/BL words without retaining a decoded object for every instruction; later recovery succeeds under the same heap limit. Legacy transitive raiser classification is restricted to the independently witnessed target, and unknown exception-factory guesses are left unresolved.

The native array allocator at 0xB5FE50 has normal allocation and conditional overflow paths. The earlier transitive exception-name heuristic incorrectly emitted an OverflowException allocation in place of an int array. Strict size/header/return-flow recognition, witnessed independently from String, BitConverter and Convert families, now recovers that call as array allocation. The original routine matches 582 cases / 3,468 comparisons at explicit initialized-class, element-size, allocation, memset and overflow boundaries. No GC/allocation-failure parity is implied. The VersionContainer source now contains new int[4] where the old export cast OverflowException to int[]. Boolean-result and integer/array-length propagation repairs address a separate source of invalid object-typed arithmetic; remaining warnings are counted above.

Ghidra .plt was initially non-executable in this loader's analysis model. All 656 16-byte thunks match original NSO text, the ADRP/LDR/ADD/BR layout and import GOT addresses. Only that analysis flag was corrected; no source code bytes or OS page permissions changed. Seventeen new native targets and three repaired import-thunk exports are retained separately. Imported stubs do not constitute the implementations of their external libraries.

The current ARM64 managed argument resolver consumes one integer register per non-floating parameter. Original ObscuredInt conversion/setter instructions consume both X1/X2 for one 16-byte value, and its return conversion produces X0/X1. The resolver's single argument/result operand model loses that distinction. Native-tested 32-byte ObscuredLong returns use X8, which the tool separately models as a hidden result buffer. The scoped audit identifies 14 ObscuredInt-return and 27 by-value-argument metadata records as review candidates; it does not claim every candidate is incorrect or reachable. Complete multiword entry/call/return/stack/SSA/CIL support is required before trusting those recovered bodies. See reports/arm64-currency-abi-gap.json.

The stock Dumper runtime header had class and array layouts inconsistent with the native binary. The v2 type archive gates static_fields=0xB8, vtable=0x128, array elements=0x20 and Hit.damage=0x1C. Old typed exports are superseded by typed-behavior-ai-layout-v2. Type names outside validated offsets still require individual review.

Native assembly confirms that FightScene.FixedUpdate is a five-instruction null check/tail call into Fight.Draw. Some Ghidra pseudocode expands the tail call and displays the Draw loop inside its caller. Reports identify the real machine-code location rather than treating the expanded pseudocode as original function boundaries.

Remaining substantive work includes full collision/damage/AI semantics, progression/reward/economy transitions, platform feature gates, save hash/schema and failure behavior, shaders and representative runtime comparisons. See feature-parity.csv. No Windows game build or FPS result is claimed.
