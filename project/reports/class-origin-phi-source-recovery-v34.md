# Exact class-metadata Phi recovery

SCOPED_EXACT_CLASS_PHI_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE

Full clean decompilation and portable game source remain incomplete.

Actual GetSafe CIL:3 exact constructor requests versus prior2 plus1 raw diagnostic; required field reload retained. Four raw class-flag diagnostics remain.

| Complete matching-reference source check | Firstpass diagnostics | Main diagnostics |
|---|---:|---:|
| nso-class-guard-load-v33 | 19219 | 30061 |
| nso-class-origin-phi-v34 | 19103 | 29900 |

Required gates: 29/29 passed.

The correlated GetSafe body gains one exact managed constructor request in place of its raw helper diagnostic; no global recovered-method count is inferred. GetSafe and Unload raw class-flag/cold-CFG paths remain unresolved; post-cctor fields and branches are preserved. Actual GetSafe CIL is inspected, not executed. Independent constructor/native fixtures, current bounded runtime regressions,44-assembly syntax/stack checks and full-source compiler outcomes have distinct scopes. Compiler diagnostic-line deltas include cascades and are not completion percentages. Full clean decompilation, gameplay equivalence and every platform port remain incomplete.
