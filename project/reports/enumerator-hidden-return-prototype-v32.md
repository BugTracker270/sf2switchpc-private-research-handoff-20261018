# Exact native return-buffer prototype

Status: counterfactual copied-IR investigation; no production Core, recovered DLL, source or native binary was changed. Original game code was not executed by this pipeline probe. The separate native witness executes only two reviewed native bodies at documented synthetic boundaries.

The v31 investigation (`enumerator-storage-findings-v31.md`) showed that Fight.SetStage's GetEnumerator result and its consumed enumerator occupy different recovered locals. A narrowly scoped copied-IR experiment now tests the proposed integration before modifying production recovery.

## Guards and classifier limitation

The strict existing-classifier experiment stopped before mutation. The selected shared GetEnumerator alias and the caller's actual closed List<Model>.GetEnumerator both return GenericInstanceTypeAnalysisContext values whose Definition is null; TypeSizes.UnboxedSize returns zero and ReturnsViaHiddenBuffer returns false. No generic-size classifier was changed. Exact observations are in `enumerator-pipeline-v32-prototype-blocker.json`, and original failures remain under logs.

A separate explicit `--prototype-native-buffer` mode uses a descriptor for **only** the reviewed native shared reference-enumerator body at 0x1585F60. It checks the full 36-byte body and 16-byte constructor hashes and independently indexed FDE extents. Native execution evidence is `enumerator-native-return-v31.json` (six cases, 36 checks). The independent closed metadata/layout investigation in `exact-body-range-and-closed-enumerator-v32.json` corroborates ref/int/int/ref offsets 0/8/12/16 and 24-byte size. Its offsets are inferred under sequential layout and corroborated by native instructions; zero raw generic-field offsets are not advertised as exact recovered offsets. This is not a generic struct-size rule.

All 278 concrete aliases at the exact native address must have the same base definition, GetEnumerator signature, zero managed parameters, known reference T and the matching nested Enumerator<T> return. Value, pointer, byref, open or unresolved nested generic arguments are rejected. The sole open base alias is checked only for signature identity and supplies no layout proof. The actual caller MethodInfo usage at 0x3B4CE60 is reached through the original GOT slot 0x39D61A0 and must match a registered target alias by exact base and concrete argument identities.

The initial prototype also rejected a zero UnderlyingPointer in the MethodInfo context. Local source inspection explains it: MetadataUsage.AsGenericMethodRef constructs a fresh metadata-only Cpp2IlMethodRef without assigning GenericVariantPtr. Registered generic variants receive pointers in Il2CppBinary.GetGenericMethodFromIndex. The corrected guard therefore records that zero explicitly and requires an equivalent registered alias at the direct BL target. A conflicting nonzero pointer or absent registered match still fails. The initial assumption failure remains in `logs/enumerator-pipeline-v32-native-prototype-methodinfo-pointer-failure.log`.

The caller must have the unchanged adjacent `Move X8, AddressOf(StackOffset(8))` before call86. An actual CFG scan proves native X0 has no reads across eight instructions before its next overwrite; replacing the call result cannot discard an observable native return-pointer use in this caller. Existing X1 MethodInfo remains available for later concrete managed binding.

## Copied-IR result

Only call86's destination changes from X0 to the original direct StackOffset in a fresh copied ISIL list. The ordinary existing stack normalization, SSA, metadata, type propagation, simplification and final analysis passes then run unmodified. No source or CIL operand patch is applied to production outputs.

`enumerator-pipeline-v32-native-prototype.json` records the complete guarded experiment and final assertions. The result is one closed Enumerator<Model> local, `stack_-68_v3`. GetEnumerator defines it, and MoveNext95, get_Current101 and Dispose135 all take the address of that exact local object. No scalar-zero assignment remains to that result storage; the call is its only remaining definition. These symbolic assertions support a narrow pre-SSA integration point but do not certify actual recovered CIL, source compilation, whole-method semantics or gameplay.

The independent address-taking SSA defect remains separate. In the actual v31 baseline, enum consumers use addresses and preserve the same enum slot version. A broader storage model for cases with later plain reads requires its own fixture and validation; this prototype does not change SsaForm.

Next validation after a separately reviewed production integration: regenerate actual recovered DLLs, prove GetEnumerator and all three receivers share actual CIL storage, verify the bad scalar-to-aggregate source expression disappears under exact manifest hashes, and execute a bounded actual recovered expression with documented input boundaries. Whole source must still compile and unresolved behavior must still be recovered.
