# Native leaf and exception factory recovery

IN_PROGRESS

Full clean game source is still incomplete. The following corrections have separate native, metadata and recovered-CIL gates.

| Source check | Firstpass diagnostic lines | Main diagnostic lines |
|---|---:|---:|
| v27 | 20266 | 33148 |
| v28 | pending | pending |

Corrections:

- Restore existing public nonvirtual accessors only after an exact native scalar/ref load/store plus return witness, preserving original private field flags.
- Recover complete native two-word integer field-copy leaves as managed whole-field operations before generic argument analysis.
- Recognize the reviewed no-argument returning exception factory and preserve its exact default constructor effect as an adjacent allocation/constructor pair.

Evidence:

- [accessor selection](private-access-leaf-selection-v28.json): PASS_NATIVE_LEAF_ACCESSOR_SELECTION_ONLY; 19 checks.
- [accessor native](private-access-native-store-v28.json): PASS_ORIGINAL_REFERENCE_FIELD_SETTER; 128 checks.
- [accessor recovered](recovered-leaf-accessor-nso-native-leaves-v28.json): NOT_STARTED; pending checks.
- [aggregate selection](integer-aggregate-leaf-recognition.json): PASS_SCOPED_16BYTE_NATIVE_FIELD_COPY_RECOGNITION; 24 checks.
- [aggregate native](integer-aggregate-leaf-native-fixtures.json): PASS_ORIGINAL_NATIVE_16BYTE_FIELD_COPY_FIXTURES; 6144 checks.
- [aggregate recovered](recovered-aggregate-leaves-nso-native-leaves-v28.json): NOT_STARTED; pending checks.
- [factory selection](compiler-priority-exception-factory.json): PASS_NATIVE_FACTORY_METADATA_AND_EXACT_CONSTRUCTOR_PAIR; 26 checks.
- [factory native](compiler-priority-native-exception-factory.json): PASS_ORIGINAL_NO_ARGUMENT_FACTORY_TO_MANAGED_INVOKER_BOUNDARY; 320 checks.
- [factory recovered](recovered-exception-factory-nso-native-leaves-v28.json): NOT_STARTED; pending checks.

Opt-in alternative patch only. The accessor scope excludes nested paths, addresses, generic/value receivers, effectful accessors, readonly writes and unsupported initialization contracts. Aggregate tests compare managed fields and adjacent storage; padding-byte identity, generic aggregate entry/call/return and GC remain outside scope. Exception tests reach an explicit managed invoker boundary; host CLR constructor checks do not execute the Nintendo GC, original constructor implementation, full caller or gameplay. Compiler diagnostic counts include cascades and do not measure completion. Full game source and port readiness remain incomplete.
