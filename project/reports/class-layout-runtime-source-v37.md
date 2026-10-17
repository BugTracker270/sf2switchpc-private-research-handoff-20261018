# Exact common runtime class-layout initialization

PASS_EXACT_COMMON_RUNTIME_CLASS_INIT_BOOL_ABI_AND_EFFECTS

B04F60 matches the exact-release common runtime `bool Class::Init(Il2CppClass*)`: one class pointer in X0 and true on normal return. A void-return interpretation is unsupported. Incoming X1 is not a second managed argument.

15 source/native checks passed; original initialized-path witness: 512 cases / 3,584 checks, plus one stopped null-assert boundary. Exact native FDE is 140 bytes, including unlock/resume cleanup; prior 112-byte fixtures covered a narrower initialized path.

The official archive matches its published MD5. Its actual size exceeds the API catalog byte count by 272; both observations and the local SHA-256 are recorded. Only common runtime sources and a license reference were extracted as local ignored data. The installer was never executed.

Preserved effects:

- Assert a non-null class pointer; initialized classes return true without metadata writes on the measured path.
- For an uninitialized class, acquire the metadata mutex and run InitLocked with RAII unlock on normal/exceptional paths.
- InitLocked recursively prepares generic/array-element/parent metadata, methods, interfaces/vtable, hierarchy, fields, events/properties/nested types, GC descriptors and generic context as applicable; it changes initialization state and statistics.
- Managed .cctor execution belongs to the distinct Runtime::ClassInit path with constructor-state guards and Runtime::Invoke; Class::Init must not be translated as RunClassConstructor.

Limits and unresolved translation:

- Normal return is true; null input reaches a native assertion boundary, not a measured false return or managed NullReferenceException.
- Uninitialized setup may allocate and call other runtime metadata helpers. Their complete failure behavior is not executed here. The original wrapper has real cleanup/unwind instructions; those effects are not removable.
- The shipped common source is from the exact official Windows editor release. Platform-specific SDK/compiler implementation equivalence is not assumed; original native instructions independently anchor the wrapper signature, source assertion line and behavior.
- The 512-case native witness executes only the already-initialized path. One null case stops before the imported assertion; actual assertion termination, locks, InitLocked, unwinding and managed .cctor are outside that execution witness.
- ABI correction can reject phantom incoming X1 arguments without erasing the helper. A managed metadata-readiness translation still requires a separate contract and .cctor-negative CLR evidence; none is implemented.

Exact source locations/hashes are in the JSON. Detailed source excerpts and original instructions remain in ignored local analysis. No Core changes, helper removal or managed translation occurred.
