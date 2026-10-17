# Bounded virtual-copy proposal

The smallest next correction is the slot6 companion copy in TryGetAttribute: original native code loads function and MethodInfo together, copies MethodInfo X8→X1, then dispatches. Keep the original parameter-root proof and trace only this companion through unique available local copies within the same pure dispatch block. Preserve the loads and their other uses.

A separate extension could accept FirstAttribute’s slot5 receiver as the unique result of its prior proven get_Attributes call. It needs immutable producer/root identities, dominance, no escape and fresh emission validation; type equality alone is insufficient. Do not reload a getter or recreate a producer.

The JSON records15 negative fixture families. Preserve the existing43 selection fixtures,218 checks and99 host CLR cases. Void targets, explicit arguments and arbitrary field roots remain outside this proposal. No Core change, fresh recovery or new accepted production call is claimed.
