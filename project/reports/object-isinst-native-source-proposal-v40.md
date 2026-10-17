# Exact Object::IsInst ABI candidate

Pinned official Unity2018.1.9f1 source and original244-byte FDE0xB5B390..0xB5B484 agree on Object*(Object*,Class*): X0 original object/null, X1 target class, X0 same object/null return. The legacy finder currently returns0 because its Type.IsInstanceOfType anchor has no BL. There are no registered method aliases at this target.

The first safe phase is ABI-only: retain the numeric diagnostic/effect and original X0 destination plus original X0/X1 arguments; discard only the verified raw capture suffix and seed a conflict-checked canonical Object result. No isinst/array-store semantics are restored by this step. COM/WinRT queries, Release, metadata initialization and assertion paths remain unresolved effects.

The selected original constructor contains28 eighteen-operand calls. Its first X1 is a unique native/SSA runtime array klass.element_class load at+0x40. Fresh logs contain3,355 array-to-nint diagnostics within four lines of this helper (3,508 total); the text-word inventory has13,188 matching BL encodings in4,783 original FDEs. These are associations, not expected diagnostic reductions or proof of semantic recovery.

A later semantic phase must preserve runtime covariance, object/null identity and original type-failure-before-bounds order. Static element isinst and blind stelem.ref fusion have concrete counterexamples. Separate Single XOR failures originate in FCMP being lowered as integer overflow flags plus missing FSQRT, demonstrating that one generic cast/type patch cannot repair all families.
