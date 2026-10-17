# Bounded CFG initialization recovery

RECOVERED_GAME_EXECUTION_LIMITATION_CONFIRMED

Full clean decompilation remains incomplete.

| Source check | Firstpass diagnostic lines | Main diagnostic lines |
|---|---:|---:|
| v30 | 18762 | 28906 |
| v31 | 19480 | 30393 |

Evidence:

- [native cfg recognition](cfg-initialization-recognition-v31.json): PASS_SCOPED_CFG_INITIALIZATION_RECOGNITION; 0 cases / 26 checks.
- [typed class constructor lowering](legacy-class-init-lowering-v31.json): PASS_LEGACY_CLASS_INIT_TYPED_LOWERING_AND_CLR_CONTRACT; 80 cases / 120 checks.
- [actual recovered codec](recovered-value-this-nso-cfg-init-v31.json): RECOVERY_EXECUTION_LIMITATION_CONFIRMED; 0 cases / 0 checks.
- [recovered boxing](recovered-primitive-box-nso-cfg-init-v31.json): PASS_RECOVERED_INT32_BOX_EXPRESSION_AT_TYPED_VALUE_BOUNDARY; 80 cases / 240 checks.

Native recognition is limited to exact FDE-bounded selected legacy value-receiver bodies and reviewed initializer identities. Metadata assurance flags are replaced only after exact native witnesses; scheduled arithmetic and semantic branches remain. Class-constructor effects use the exact existing managed RuntimeHelpers.RunClassConstructor handle API only after typed metadata-origin proof; unknown pointers stay diagnostic. CLR constructor-contract fixtures and actual recovered game-code comparisons have separate scopes. The game codec comparison uses explicit supplied static state and native absent-detector fixtures; active detector callbacks, general aggregate ABI, serialization attributes, the complete source build and later ports remain unverified. Compiler diagnostic counts include cascades and do not measure completion.
