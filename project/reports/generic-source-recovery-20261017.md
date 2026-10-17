# Generic field, aggregate and parameter recovery

SCOPED_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE

The full clean decompile remains incomplete. These are original tool corrections with bounded native/CIL evidence.

| Run | Firstpass diagnostic lines | Main diagnostic lines | Recovered execution |
|---|---:|---:|---|
| nso-generic-fp-fields-v22 | 21338 | 36018 | RECOVERED_NESTED_GENERIC_CALLER_LIMITATION |
| nso-generic-fp-tail-v23 | 21360 | 36020 | RECOVERED_NESTED_GENERIC_CALLER_LIMITATION |
| nso-nested-hfa-v24 | 21360 | 36015 | RECOVERED_NESTED_GENERIC_CALLER_LIMITATION |
| nso-sparse-params-v25 | 21360 | 35980 | PASS_RECOVERED_NESTED_HFA_AND_CALLER_NATIVE_COMPARISON |
| nso-type-handle-v26 | 21055 | 35788 | PASS_RECOVERED_NESTED_HFA_AND_CALLER_NATIVE_COMPARISON |
| nso-generic-ctor-v27 | 20266 | 33148 | PASS_RECOVERED_NESTED_HFA_AND_CALLER_NATIVE_COMPARISON |

Corrections:

- Closed-generic field layout with observed inherited field offsets and tail-padding reuse.
- Scalar FP access widths and nested managed field addresses for reads and stores.
- Analysis-warning tails now terminate by throwing instead of falling off the method.
- Recursive metadata-validated homogeneous FP aggregates; unsupported layouts remain diagnostic.
- Surviving parameters keep their original signature position when earlier arguments are optimized out.
- A literal token stays RuntimeTypeHandle when required by the managed signature; ordinary Type conversion remains separate.
- Adjacent closed-generic reference allocation/constructor pairs match canonical definitions and arguments, while receiver/block/order guards remain.

Evidence:

- [Original complete caller](native-fp-class-guard-caller.json): 256 cases / 1,024 checks at the stated runtime boundary.
- [Original wrapper identities](native-nested-hfa-identity.json): 240 cases / 720 checks, including arbitrary float bit patterns.
- [Recovered caller and wrapper comparisons](recovered-nested-tween-nso-sparse-params-v25-with-identities.json).
- [Metadata/layout and sparse-parameter checks](generic-field-path-v25.json).
- [Type-handle expression contract](recovered-type-handle-token-nso-type-handle-v26.json): isolated CLR expression; not original ARM64 or full-getter validation.
- [Closed-generic construction expression](recovered-constructor-nso-generic-ctor-v27.json): actual CIL at the host CLR List<T> boundary, stopping before Unity base initialization.
- [Earlier failure isolated to an unterminated warning tail](recovered-nested-tween-nso-generic-fp-fields-v22-tail-experiment.json). This probe experiment is not unchanged-CIL acceptance.
- [Arm ABI definition](https://github.com/ARM-software/abi-aa/blob/2025Q1/aapcs64/aapcs64.rst), sections 5.10.5 and 6.8.

Opt-in experimental tool patch remains separate from canonical v19. Native tests are bounded instruction harnesses. The original full caller uses an explicit class-initializer boundary; recovered execution substitutes exact isolated field storage and rejects reachable diagnostics. Stack-spilled HFAs, integer multiword aggregates, full runtime ordering, other call paths and full game source remain unverified. Constructor expression checks use the host CLR List<T> contract and stop before Unity base initialization; Nintendo allocator/GC and the full constructor are unverified. Compiler diagnostic counts include cascades and are not completion measures.
