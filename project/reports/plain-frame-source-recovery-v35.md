# Ordinary plain-frame recovery

SCOPED_PLAIN_FRAME_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE

Full clean decompilation and portable source remain incomplete.

| Complete matching-reference source check | Firstpass diagnostics | Main diagnostics |
|---|---:|---:|
| nso-class-origin-phi-v34 | 19103 | 29900 |
| nso-plain-frame-cfg-v35 | 18806 | 29779 |

Required gates: 35/35 passed.

Only the new ordinary extension requires an exact plain zR frame with empty FDE augmentation. The older selected route still contains twelve zPLR bodies with unverified exception semantics. Bounds do not recover cleanup, personalities, action tables or exception edges. Unsupported cold/reload shapes remain explicit. Scope-bound parser, constructor, native/IR and runtime evidence are separate; no global method-recovery percentage is inferred. Both complete game source assemblies must compile and undergo behavioral verification before any clean-decompile or portable-game claim.
