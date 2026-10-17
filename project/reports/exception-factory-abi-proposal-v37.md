# Overflow factory ABI evidence

Original helper0xB4D960 has an exact52-byte frame and matches the official2018.1.9f1 common-runtime declaration `Il2CppException* GetOverflowException(const char* msg)`. Its incoming X0 is the message pointer; incoming X1 is never read. The wrapper constructs namespace/type arguments internally and tail-calls the original exception factory.

A narrow ABI-only correction may keep the numeric Call/result and sole X0 argument, allowing dead phantom-register uses to disappear. It must preserve the diagnostic, returned exception and separate throw. The source/native factory allocates, initializes and sets a message, with cleanup paths; translating or erasing it is outside this proposal.

Thirteen static evidence checks pass. No original factory execution, Core edit, managed translation or full source readiness is claimed. The expected removal of the remaining Stream companion load needs a new production-stage/CIL result.
