# Switch versus mobile evidence policy

The supplied base + 1.1.0 patch is the only authoritative game-code/data input. No Android APK or mobile game assets were acquired. Guide/mod repositories are format references unless a specific equivalent native method and schema can be demonstrated.

Switch-specific evidence includes two-player PvpScene inputs/controller switching, four serialized save-slot bindings, Nintendo account/filesystem wrappers, controller prompt atlases and Sensei quest data. See local-sparring.md, save-research.md and asset-integrity.md.

Residual mobile raids/social/ads/Forge/energy classes and settings remain in the binary/data. Their presence is not evidence of an available Switch mode. Internal settings even retain mobile-facing flags; compile-time stubs and platform entry paths must decide reachability. SystemProperties.SetFrameRate, for example, is a single RET here despite its meaningful mobile-facing name.

The master specification's removed-mode list is an acceptance requirement. It is not automatically marked verified from source names or a mobile guide. Offline progression, balancing, all removed-mode gates and shortened duel waits still need explicit native/runtime checks.
