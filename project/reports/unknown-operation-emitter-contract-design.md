# Unknown-operation emitter contract — design only

Fresh v40 offline evidence shows that `Cpp2ILInjected.Cpp2ILHelpers.NoteDecompilerIssue` contains only `ret`. The original profile constructor calls it 32 times, including 28 Object::IsInst sites. Those 28 results have no emitted assignment and can read implicit InitLocals null. Numeric diagnostics therefore preserve an annotation scaffold, not the original call effects or results. See `recovered-object-isinst-abi-nso-object-isinst-abi-v40.json` for exact body/assembly hashes and the unexecuted scope.

A separate experimental emission contract should fail explicitly when a reachable operation lacks semantics. An injected helper with an exact `NotSupportedException` throw body could receive the owner, original address/IR index and unresolved operation category. Unsupported native calls must reach it before omitted argument evaluation or any fabricated result read; unsupported memory/conversion/field operations need the same policy. Diagnostic-only listing output may remain a separate clearly labelled artifact.

Such a change would expose incomplete recovery. It would not restore native argument evaluation, helper return values, exception order, initialization, COM behavior or a runnable game, and it must not count as clean decompilation progress by itself. Whole-source compilation and reachability still require independent validation.

Before implementing it, define and test at least these boundaries:

- Actual injected helper metadata/body is inspected in a complete output; a fallback Console.WriteLine fixture is insufficient.
- A reachable unknown operation throws an exact diagnostic exception before any default-result continuation. A known recovered operation retains its original body.
- A proven unreachable unknown branch remains excluded by its explicit fixture boundary; the probe does not delete or rewrite it to pass.
- All unsupported emitter paths are inventoried. A blanket successful helper call must not silently stand in for an unresolved allocation, load, field access or return value.
- Existing diagnostic-scaffold reports remain historical evidence. New failure counts are reported honestly and do not imply newly recovered game errors.

No Core source, helper body, recovered CIL, game constructor or runtime behavior was changed for this design.
