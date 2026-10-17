# Fresh array class-origin design

Design only. The hash-bound original constructor stage contains four typed NewArr roots feeding 28 runtime element-class projections: two String[] sites and 26 InputControlMapping[] sites. These are textual candidates; none is accepted for semantic translation.

The first next step is a read-only operand-identity, unique-definition, dominance and complete-use/escape probe on the current CFG. ArrayRecovery runs after SSA removal, so a typed local or earlier textual definition is insufficient. Parameter/field/covariant arrays, Phi roots and unresolved storage must reject.

Class provenance is separate from IsInst semantics. Official source shows a COM/WinRT branch and metadata initialization on non-identical ordinary class pairs. The two literal String cases provide a narrower starting candidate; exact original class identity, unchanged native behavior, initialization timing and CLR .cctor-negative tests remain required. The current native ABI oracle supplies assignability and does not prove it.

A future result-bearing isinst operation must preserve the original null/failure branch, then bounds checks and original store. No helper removal, constant/argument substitution, stelem.ref fusion or Core implementation is authorized or performed by this design. Numeric helper argument/return semantics and the full clean portable decompile remain unresolved.
