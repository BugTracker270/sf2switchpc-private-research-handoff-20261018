# Bounded CFG initialization recovery

SCOPED_INITIALIZATION_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE

Full clean decompilation remains incomplete.

| Source check | Firstpass diagnostic lines | Main diagnostic lines |
|---|---:|---:|
| baseline | 19480 | 30393 |
| v31b | 19326 | 30393 |

Evidence:

- [native cfg recognition](cfg-initialization-recognition-v31.json): PASS_SCOPED_CFG_INITIALIZATION_RECOGNITION; 0 cases / 26 checks.
- [typed class constructor lowering](legacy-class-init-lowering-v31.json): PASS_LEGACY_CLASS_INIT_TYPED_LOWERING_AND_CLR_CONTRACT; 80 cases / 120 checks.
- [actual recovered codec](recovered-value-this-nso-static-getter-v31b.json): PASS_ACTUAL_RECOVERED_VALUE_THIS_CODEC_VS_ORIGINAL_NATIVE; 342 cases / 2052 checks.
- [recovered boxing](recovered-primitive-box-nso-static-getter-v31b.json): PASS_RECOVERED_INT32_BOX_EXPRESSION_AT_TYPED_VALUE_BOUNDARY; 80 cases / 240 checks.
- [native static getter](native-static-getter-v31b.json): PASS_ORIGINAL_STATIC_GETTER_AT_METADATA_ASSURANCE_BOUNDARY; 64 cases / 512 checks.
- [static getter selection](static-leaf-getter-selection-v31b.json): PASS_STATIC_GETTER_NATIVE_METADATA_AND_NEGATIVE_GUARDS; 0 cases / 29 checks.
- [recovered static getter](recovered-static-getter-nso-static-getter-v31b.json): PASS_ACTUAL_STATIC_GETTER_AND_CALLER_ACCESSOR_CORRELATION; 9 cases / 24 checks.

Native recognition is limited to exact FDE-bounded selected legacy value-receiver bodies and reviewed initializer identities. Metadata assurance flags are replaced only after exact native witnesses; scheduled arithmetic and semantic branches remain. Class-constructor effects use the exact existing managed RuntimeHelpers.RunClassConstructor handle API only after typed metadata-origin proof; unknown pointers stay diagnostic. Static foreign-private reads use an existing public getter only after exact native body, metadata-owner and no-cctor proof; field visibility stays intact. CLR constructor-contract fixtures and actual recovered game-code comparisons have separate scopes. The game codec comparison uses explicit supplied static state and native absent-detector fixtures; active detector callbacks, general aggregate ABI, serialization attributes, the complete source build and later ports remain unverified. Compiler diagnostic counts include cascades and do not measure completion.
