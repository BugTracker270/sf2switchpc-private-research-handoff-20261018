# Scoped internal getter recovery

SCOPED_ASSEMBLY_GETTER_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE

Original private fields retain their visibility. The same-assembly getter route passes78 contract checks,15 original constructor-pipeline checks and118 independent fresh-output checks covering27 getters/two callers. Separate original-native evidence covers128 cases/384 checks plus a null-receiver boundary. All18 bounded regressions pass.

Matching source compiler: firstpass20,728 →20,534 (−194); main32,710 →32,710. Both complete builds still exit1. Firstpass CS0122 falls2713 →2528;99 Serializer reads use the existing internal property, while two private constructor stores remain errors.

Six added semantic diagnostics are retained: byte[]+int four times, HTTPProxy→HTTPConnectionStates once and System.Type→nint once. Independent added-diagnostic audit: 275 checks trace all six to unchanged prior invalid operations; those operations remain unresolved.

Evidence gates: 36 pass/0 pending/0 fail. Completed canonical compiler/source-manifest audit is reused explicitly; full source trees are not rehashed by this summary. Frozen40-source/tool-binary snapshots bind the historical Core independently of later tool edits. Full clean decompilation and portable source remain incomplete.
