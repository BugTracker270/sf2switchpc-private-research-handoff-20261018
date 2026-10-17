# Virtual dispatch recovery checkpoint

SCOPED_VIRTUAL_DISPATCH_VALIDATED_ACTUAL_PREFIX_EXECUTION_LIMITATION_REMAINS

Both actual Stream.ReadByte sites retain callvirt. Actual prefix execution remains blocked by a live MethodInfo diagnostic; zero runtime cases ran. Full clean decompilation and portable game source remain incomplete.

| Complete matching-reference source check | Firstpass diagnostics | Main diagnostics |
|---|---:|---:|
| nso-plain-frame-cfg-v35 | 18806 | 29779 |
| nso-virtual-dispatch-v36 | 20843 | 32879 |

Required evidence gates: 40/40; actual prefix runtime is explicitly LIMITATION.

Established regression invocations: 18/18 successful. Failed required gates: none.

Separate measured scopes: 218 synthetic contract checks / 99 authored CLR cases; 802 unchanged native cases / 9,624 checks; two unchanged actual CIL callvirt sites. None substitutes for executing the blocked actual prefix.

The codec probe retains its initial syntactic failure, then checks unchanged recovered CIL in 342 original null-detector cases / 2,052 checks with four boundary controls. Its active-detector virtual callback remains unresolved and unexecuted.

Unpromoted candidate: `src\re\tool-patches\cpp2il-sf2-hfa-experimental-virtual-dispatch-v36.patch`; SHA-256 `1de29cbf711e9bc2abfc351c213ad0acd1420a385ffb529daf79c18e6d8e553b`. The accepted earlier patch remains separate.

The two actual callvirt sites are structurally correlated, while actual prefix runtime remains blocked by a live MethodInfo companion-load diagnostic/native-int-zero placeholder. Native initialized-runtime fixtures, synthetic real-emitter CLR cases, actual production IR, read-only current CIL and full-source compilers have distinct scopes. No actual prefix runtime cases or full-game execution are claimed. Later indirect calls, class-layout metadata effects, missing exception recovery and complete source compilation remain unresolved.
