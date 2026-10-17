# Shadow Fight 2 mod (2026)

This mod unlocks all levels and equipment, and grants you unlimited money, gems, and enchantments. Android only. Verified end to end on Shadow Fight 2 `2.46.0`; nothing in the setup is tied to a particular game version.

## Background

I used to play Shadow Fight 2 a lot when I was younger and recently wanted to revisit the Titan fight without grinding through the whole game. None of the mods I found online worked on the latest version, so I tasked Claude Code with cracking the game. I gave it an Android VM and let it cook; after a lot of trial and error, it reverse-engineered the integrity checks from the obfuscated code and made me this CLI tool.

The full technical story is in [WRITEUP.md](WRITEUP.md). Essentially, editing the progress file (`users.xml`) isn't enough; the game discards any changes if the new hash doesn't match the saved hash (`users.xml.hash`). Claude figured out that the hash is computed using `users.xml` encoded a certain way, a fixed salt embedded in the APK, and a device-dependent unique ID. That last ID is tied to the app's signing certificate, so setup re-signs the game with the key in this repo and then reads the ID back off the phone. That takes three commands and no root.

## Requirements

- An Android device with Shadow Fight 2 installed, plus a USB cable
- `adb` on your `PATH`, from Android Platform Tools (`brew install android-platform-tools` on macOS)
- Android SDK build-tools for `zipalign` and `apksigner`, only needed once during setup (Android Studio's SDK Manager, or `sdkmanager 'build-tools;36.0.0'`)
- [uv](https://docs.astral.sh/uv/), which runs the scripts and fetches Python for them
- USB debugging turned on: Settings → About phone → tap **Build number** seven times, then Developer options → **USB debugging**

Plug the phone in and confirm that `adb devices` lists it as `device`. Turn USB debugging back off when you're done editing saves, because while it is on anything with USB access can read app data and install packages.

## Setup

Three commands, once per device. Start by pulling your save, because the next step uninstalls the Play Store copy and uninstalling deletes the phone-side save:

```sh
uv run pull_users_xml.py
```

Re-sign and reinstall the game's own APKs. Their bytes are unchanged apart from the signature blocks:

```sh
uv run resign_install.py
```

Then read the device value into `.env`, using a small reader app signed with the same key:

```sh
uv run capture_device_value.py --write-env
```

To check the value, launch the game once so it writes a save, then:

```sh
uv run pull_users_xml.py && uv run capture_device_value.py
```

That recomputes the hash for the pulled save and compares it with the one the game wrote. `Match` means you're set. Otherwise stop, because a wrong value only produces saves the game rejects.

Worth knowing:

- Use the committed `tools/sf2mod.keystore`. The value follows the signing certificate, so a different key gives a different value.
- Re-signing invalidates the hash on the save your Play Store copy wrote, so push the save you pulled back with `push_users_xml.py` before launching the re-signed game if you want your progress.
- On Android 7 and older, `ANDROID_ID` is device-wide, so `capture_device_value.py` just reads it and no re-signing is needed.
- A re-signed client is against the game's terms of service, and it won't have Play Store or in-app purchases. Don't do this on an account you care about.

## Editing the save file

Pull the current save files into `.local/saves/`:

```sh
uv run pull_users_xml.py
```

Edit `.local/saves/users.xml` manually. `examples/users.xml` is a maxed-out starting point you can use as a reference.

Then, push the edited save back:

```sh
uv run push_users_xml.py
```

`push_users_xml.py` computes `users.xml.hash`, snapshots the phone-side save under `.local/backups/`, force-stops the app, and pushes the XML/hash pair to the main save slot. It does the same for `users_backup.xml` when a local copy exists, and mirrors `users.xml` into the backup slot when it doesn't, so each XML keeps its own hash. Pass `--mirror-main-to-backup` to force that mirroring, or `--no-pre-push-snapshot` to skip the snapshot. Launch the app manually once the push finishes.

## Restoring a backup

Backups land in `.local/backups/<timestamp>/`. Restore one with:

```sh
uv run push_users_xml.py --restore .local/backups/YYYYMMDD-HHMMSSffffff
```

## Computing the hash only

`hash_users_xml.py` writes `users.xml.hash` beside a local file, or prints it without writing:

```sh
uv run hash_users_xml.py .local/saves/users.xml
uv run hash_users_xml.py .local/saves/users.xml --print --no-write
```

## Files

- `resign_install.py`: re-sign the game's own APKs with `tools/sf2mod.keystore` and reinstall them
- `capture_device_value.py`: read the device value off the phone and verify it against a pulled save
- `pull_users_xml.py`: pull current save files for editing
- `push_users_xml.py`: hash and push a local edited `users.xml`
- `hash_users_xml.py`: standalone hash generator
- `tools/`: the keystore, the prebuilt reader APK, and its source (`tools/deviceid-reader/build.sh` rebuilds it)
- `.env.example`: template for the per-install device value
- `AGENTS.md`: instructions for an agent walking you through the device-ID setup (`CLAUDE.md` symlinks to it)
- `WRITEUP.md`: full reverse-engineering writeup
- `examples/`: a reference save file as a starting point
- `tests/`: pytest suite covering the hash primitives. Run with `uv sync --group dev && uv run pytest`.
