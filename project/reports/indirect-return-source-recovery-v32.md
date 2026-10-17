# Reviewed indirect-return recovery

SCOPED_INDIRECT_RETURN_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE

Full clean decompilation and portable game source remain incomplete.

Actual recovered caller fragments: 5/5 cases; 12 structural and 28 runtime checks.

| Complete source check | Firstpass diagnostic lines | Main diagnostic lines |
|---|---:|---:|
| nso-static-getter-v31b | 19326 | 30393 |
| nso-enumerator-return-v32 | 19263 | 30155 |

| Required scoped gate | Result |
|---|---|
| production_adapter_23 | PASS |
| original_native_6_cases_36_checks | PASS |
| native_cleanup_tail | PASS |
| baseline_execution_failure_retained | PASS |
| actual_recovered_caller_fragments | PASS |
| raw_class_init_31 | PASS |
| raw_class_init_survey_binding | PASS |
| native_class_requests_preserved | PASS |
| class_constructor_effect_contract | PASS |
| bounds_api_regression | PASS |
| cfg_matcher_regression | PASS |
| recovered_aggregate-leaves | PASS |
| recovered_boolean-setter | PASS |
| recovered_constructor | PASS |
| recovered_currency-scalars | PASS |
| recovered_exception-factory | PASS |
| recovered_leaf-accessor | PASS |
| recovered_nested-tween | PASS |
| recovered_primitive-box | PASS |
| recovered_scalars-isolated | PASS |
| recovered_static-getter | PASS |
| recovered_type-handle-token | PASS |
| recovered_value-this | PASS |
| recovered_vector3 | PASS |
| syntax_44_assemblies | PASS |
| stack_44_assemblies | PASS |
| both_source_compiler_counts_before | PASS |
| both_source_compiler_counts_after | PASS |

Evidence remains separated:

- Original ARM64 bodies: unchanged native buffer-return execution and FDE/call-site provenance.
- Copied-IR experiment: explanatory prototype, never promoted to a production execution pass.
- Actual production CIL: original caller fragments with explicit host member/input/local boundaries.
- Whole-source builds: complete compiler results remain separate from scoped runtime success.

Original native execution, copied-IR prototypes, actual recovered CIL at explicit host boundaries, syntax/stack checks and whole-source compilation have distinct scopes. The reviewed 24-byte reference-enumerator SRET binding is one pinned native caller/body/metadata family, not general generic layout or ARM64 ABI completion. Raw class initialization retains semantic constructor requests only under exact ABI/dead-result/type-origin proof; one ambiguous origin remains unresolved. Caller fragments preserve original local indices, input/member instructions and stores; harness looping and host List<object> are explicit boundaries. They do not execute all of SetStage, combat, native runtime/.cctor bodies, save logic, or whole-game behavior. Full clean source and all ports remain incomplete; compiler diagnostic counts include cascades.
