# Switch local versus evidence

Updated 2026-10-17T08:26:34.003364+00:00. Static analysis only; no two-controller gameplay test occurred.

The original Pvp scene is level8 and contains PvpScene. PvpScene metadata includes PlayerOneInput and PlayerTwoInput, independent character templates, location selection and controller-switch methods.

The original level7 MenuItemButton component **540** has an enabled UnityEvent binding to GeneralMenuScene component **587**, method **ShowPvp** (void call mode 1; the stored string argument is gotoSparring). The binding is reproduced from the sequential component decode in analysis/assets/pvp-entry-bindings.json. ShowPvp (`0xE6ED90`) starts a delay coroutine. Its MoveNext (`0xE6F970`) unsubscribes controls, waits approximately 0.12 seconds, sets ListSF.GameMode to **2**, clears DelayCoroutine, and calls GoToModule with module **8**. This entry path does not read AssemblyController.ShowPVP. The shared AssemblySettings ShowPVP=0 value therefore does not establish that Switch Sparring is disabled.

PvpScene static initializer (`0xD974D0`) allocates two InputData objects using distinct player/control indices `(0, 2, 0)` and `(1, 2, 1)`. HaveSecondPlayer (`0xD94FD0`) reads GamePadController.DevicesCount and tests greater than one. StartFight (`0xD961F0`) resolves `PvpBattle|pvp|1`, clears fight lists, obtains the two selected model parameter sets with player IDs 0 and 1, and adds them as player/warrior before entering the fight flow. Input switching methods are at `0xD971B0`, `0xD97380`, `0xD97260`, `0xD97430`.

This identifies the local versus implementation separately from residual MultiplayerSF raid/social classes. Device ownership, Joy-Con splitting, disconnect/pause, character unlock rules and every match outcome still require deeper tracing and runtime tests.
