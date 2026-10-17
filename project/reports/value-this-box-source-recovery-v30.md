# Value-this bodies, primitive boxing and addressed storage

SCOPED_BODY_SELECTION_AND_BOXING_VALIDATED_RUNTIME_GUARDS_UNRESOLVED

Full clean decompilation remains incomplete. Actual recovered InternalDecrypt is still blocked by runtime initialization diagnostics.

| Source check | Firstpass diagnostic lines | Main diagnostic lines |
|---|---:|---:|
| v29 | 18066 | 28290 |
| v30 | 18762 | 28906 |

Corrections:

- Select exact unboxed native FDE bodies for 287 unique value-this adjustors, keeping registered pointers and rejecting four ambiguous wrappers.
- Recognize the reviewed boxing helper only for concrete eligible primitive types with initialized typed storage and no original static constructor.
- Retain original initializing copies when addresses, array elements or array length operands read their storage; preserve storage identity.

Evidence:

- [pointer observations](value-this-pointer-observations.json): CPP2IL_REGISTERED_POINTER_OBSERVATIONS_ONLY; not a numeric scope checks.
- [body selection](value-this-thunks-v30.json): PASS_SCOPED_VALUE_THIS_THUNK_SELECTION_AND_ALIASES; 35 checks.
- [native adjustor equivalence](integer-aggregate-adjustor-native-proof.json): PASS_ORIGINAL_BOXED_ADJUSTOR_VS_UNBOXED_CODEC_AND_FIXTURES; 10240 checks.
- [native boxing](native-scalar-boxing-v30.json): PASS_ORIGINAL_NON_NULLABLE_SCALAR_BOX_PAYLOADS_AT_GC_COPY_BOUNDARIES; 17920 checks.
- [boxing ir](scalar-boxing-validation-v30.json): PASS_TYPED_SCALAR_BOX_DISCOVERY_AND_CALLER_IR; 28 checks.
- [liveness before](addressed-storage-liveness-before-v30.json): ADDRESSED_STORAGE_INITIALIZATION_LOSS_CONFIRMED; not a numeric scope checks.
- [liveness after](addressed-storage-liveness-after-v30.json): PASS_ADDRESSED_COPY_INITIALIZATION_AND_IDENTITY_PRESERVED; not a numeric scope checks.
- [recovered boxing](recovered-primitive-box-nso-value-this-box-v30.json): PASS_RECOVERED_INT32_BOX_EXPRESSION_AT_TYPED_VALUE_BOUNDARY; 240 checks.
- [recovered value this](recovered-value-this-nso-value-this-box-v30.json): RECOVERY_EXECUTION_LIMITATION_CONFIRMED; 0 checks.

Native boxing uses explicit GC-allocation/imported-memcpy boundaries. The CLR boxing expression validates one actual Int32 caller and its original input provenance; it does not certify all boxing callers or full method behavior. Value-this body selection and native boxed/unboxed equivalence do not certify recovered method execution: InternalDecrypt still has eight reachable runtime metadata/class-initialization diagnostics and its actual CIL probe runs zero cases. No fields are reinterpreted by an assumed header subtraction, no method body is filled with a default to pass tests, and full clean source remains incomplete. Compiler counts include cascades and are not completion percentages.
