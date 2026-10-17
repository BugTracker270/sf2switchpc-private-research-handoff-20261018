# Typed unique call-result receiver design

Design only. The original FirstAttribute108-byte body passes the getter result in X0 directly into the slot5 Count dispatch. Current v38 IR has one typed getter Call12, its exact result local used by the class read13 and unresolved virtual Call16. Metadata declares XmlNamedNodeMap.get_Count as slot5 with Int32 return.

A separately tagged call-result origin can preserve the existing parameter path. Bind the unique original producer instruction/target/destination/reference return type, independently trace the receiver and class source to that same immutable local, and retain original slot/companion, pure-window, availability and escape guards. Revalidate producer provenance at emission and protect its root during copy coalescing. Limit the initial extension to one producer layer; already-proven parameter-root virtual producers are the concrete FirstAttribute case.

The JSON lists16 required guards and25 negative fixture families. Current Count remains unresolved; no Core code or original inputs were edited and no new native/managed case was executed. Full native disassembly and IR remain in ignored analysis.
