# Exact native helper signature recovery

OBJECT_ISINST_ABI_ADDED_DIAGNOSTIC_REVIEW_PENDING

The original two-input Object::IsInst signature passes 57 contract checks, 41 original-caller stage checks and 41 fresh-output checks. All 18 bounded regressions pass. Native wrapper testing covers 1,034 cases / 8,272 checks at an explicitly supplied assignability boundary.

The generated diagnostic helper is a bare return. It neither logs nor throws; the sampled constructor still has 28 unassigned results that can read as implicit null. Five sampled Array bodies remain default stubs. No helper return, class evaluation or assignability behavior has been implemented.

Assembly-CSharp-firstpass: 20,534 → 20,393 compiler diagnostic lines (-141); full build fails.
Assembly-CSharp: 32,710 → 32,399 compiler diagnostic lines (-311); full build fails.

Evidence gates: 37 pass / 1 pending / 0 fail. Frozen 41-file sources and three exact tool binaries bind the historical run. Full clean decompilation and portable game source remain incomplete.
