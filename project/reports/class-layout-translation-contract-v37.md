# Bounded class-layout translation contract

PASS_BOUNDED_CLASS_LAYOUT_TRANSLATION_CONTRACT_EVIDENCE

The first proposed candidate is the exact resolved System.Byte[] type. Normal native Class::Init returns true; its metadata/layout effect and failures must remain distinct from managed .cctor. No translation or eligibility implementation exists.

Evidence: 15 exact-source/native checks; initialized native path 512 cases / 3,584 checks; separate host CLR witness 60 checks / 44 observations. Forty metadata observations occurred before deliberate constructor positive controls and left counted/throwing .cctor canaries untouched.

Proposed contract:

- Initially admit only the exact resolved System.Byte[] SZARRAY type from original metadata at the reviewed B04F60 calls; resolve actual assembly/type identity, rank and element identity rather than FullName alone.
- Require the exact original helper/FDE/hash/source identity and one klass input; preserve its Boolean result and ordering. Incoming X1 and other raw ABI registers are not extra managed parameters.
- Require a valid non-null exact known class/type representation, original Byte metadata without .cctor and a host Byte[] type with no array/element initializer. Reject open/generic/custom/reference-element/multidimensional/bounded arrays and other classes in this first candidate.
- A possible host operation is obtaining the exact runtime type handle/type metadata, then returning true only on normal completion. The witness measures TypeHandle/GetTypeFromHandle and metadata reflection; it does not implement a replacement helper or authorize eliminating the metadata-readiness effect.
- Do not invoke RuntimeHelpers.RunClassConstructor, instantiate an element or use managed .cctor as a substitute. Keep the separate native Runtime::ClassInit semantic request separate and ordered.
- Validate actual emitted CIL/callsite state and constructor-counter negatives before promotion; preserve diagnostics for unsupported types/failure states instead of producing a default result or silently swallowing exceptions.

Unresolved before production acceptance:

- The proposed operation is an inferred host-runtime adaptation, not a recovered original C# method. No production translation exists, and no exact native cold initialization-to-CLR equivalence is claimed.
- Native null assertion/termination, metadata allocation failure, recursive setup failure, locking and cleanup/unwind are not mapped to CLR failures. Do not assume unconditional success from the observed normal true return.
- The common array factory/source zero-initialization model is source evidence; the actual target runtime array-class factory and a concrete cold Byte[] heap initialization were not executed in this witness.
- The four frozen typed raw-call candidates are static inventory only. Actual future callsite/provenance/registered alias and result/side-effect ordering gates remain unimplemented.
- The host CLR metadata probe deliberately invokes counted/throwing .cctor only in separate positive controls after forty metadata observations. This does not permit .cctor execution in a translated layout operation.
- Other primitive arrays, Boolean/Char with original constructor metadata, custom classes, reference-element arrays, generics and unknown metadata require separate eligibility/equivalence evidence.

Unity source remains local and ignored; the public patch contains original probes/reports only. No Core changes or helper removal occurred.
