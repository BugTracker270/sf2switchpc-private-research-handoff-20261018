# v36 codec regression diagnosis

The original v36 CIL passes all342 absent-detector fixtures (2052 comparisons,342 boundary checks). The initial failure was a scope-analysis mismatch: syntactic reachability included the active-only unresolved callback. A one-case unchanged-method invocation ruled out CLR import rejection. The corrected probe pins the exact getter/body, proves the single null branch, checks four controls and leaves the callback diagnostic in place.

The callback remains unresolved: metadata slot7 returns void and its receiver is a unique static-field SSA value rather than a parameter. Native BLR0x7A90B0 is immediately followed by MOV W0,W20 at0x7A90B4, proving its raw X0 result is dead locally. Future recovery needs deep raw-result liveness and immutable producer/root provenance; no Core change or active-callback execution is claimed.

The initial failure, original CIL and detailed native/SSA evidence remain on the USB. Full clean decompilation remains incomplete.
