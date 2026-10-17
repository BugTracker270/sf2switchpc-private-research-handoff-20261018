# Bounded exception metadata parser

PASS_BOUNDED_EXCEPTION_METADATA_PARSER

38 synthetic tests and 15 original-evidence checks; 0 integration failures.

The reusable parser reads a bounded LSDA/action/type-table subset, explicit encoded pointer references, a narrow CFI state program and simple C++ RTTI names. The unit suite requires no game files.

Its original-input adapter reproduces the earlier independent UnloadDependencies inspection: three protected ranges, a typed-wrapper action followed by cleanup, the same native wrapper RTTI, and the same CFA/saved-register states. Full original instructions remain in ignored local analysis.

Implemented contracts:

- 64-bit bounded cursor/LEB and explicit absolute/PC-relative/indirect pointer references; encoded zero remains null.
- Bounded unsigned-32 call-site ranges, fixed-width type table, signed action back-links and shared chains.
- Reject cycles, overlapping records/ranges, truncated/outside type entries, negative exception specifications and unsupported forms.
- Narrow per-instruction CFI state observations with bounded registers/PC/stack, validated initial state and explicit unsupported opcodes; shared-PC intermediate observations are not finalized unwind rows.
- Caller-supplied checked relocation resolution plus bounded simple C++ class RTTI name reading; no managed catch inference.

Remaining scope:

- General LSDA encodings, exception specifications and arbitrary C++ inheritance/RTTI structures.
- General DWARF CFI expressions, remember/restore, stack unwinding or SDK personality execution.
- EH-aware ISIL/SSA, managed region emission, game exception behavior or portable source completeness.

No Core code changed or built. No unwind or recovered game method executed, and no exception region was emitted. Full clean decompilation remains incomplete.

Run the synthetic suite alone with `python -m unittest discover -s tests -p test_exception_metadata.py -v`. Run the USB-local integration with `python src/re/tools/validate_exception_metadata.py`.
