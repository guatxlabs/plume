# plume-agent (#16) — CI & cross-OS runtime validation

[English](CI.md) | [Français](CI.fr.md)

The endpoint agent is a **standalone** binary that runs ON the desktop
(Linux / Windows / macOS), not in the SOC pod. It reads the OS's **native**
event sources through platform-specific code:

| OS      | Native source            | Mechanism                                   | cfg guard                        |
|---------|--------------------------|---------------------------------------------|----------------------------------|
| Linux   | journald                 | `journalctl` subprocess                     | `cfg(target_os = "linux")`       |
| Windows | Windows Event Log        | **FFI `windows`-rs 0.58** (EvtQuery/EvtNext/EvtRender/EvtCreateBookmark) + SCM | `cfg(target_os = "windows")` |
| macOS   | unified log              | `log show` subprocess + launchd (`launchctl`) | `cfg(target_os = "macos")` |

The Windows/macOS code is **cfg-gated**: it is **never compiled** in a
Linux build. A local `cargo build` on the dev box (Linux) therefore does **not**
prove that the Event Log FFI or the unified-log reader compile and link. That
is where GitHub Actions CI comes in.

## Where the Win/Mac runtime validation happens

**On GitHub Actions, once the repos are pushed to GitHub** (launch plan
Week 1). The `windows-latest` and `macos-latest` runners are **real
machines** running Windows and macOS — not emulators. The workflow
[`.github/workflows/agent-ci.yml`](../.github/workflows/agent-ci.yml) runs a
**matrix** `[ubuntu-latest, windows-latest, macos-latest]` which, on EACH OS:

1. `cargo build --release` — compiles that OS's native code (the Event Log FFI
   on Windows, the unified-log reader on macOS);
2. `cargo test` — runs the tests (parsing + spool/cursor roundtrips);
3. network-free smoke — `plume-agent --version` / `--help` (the binary starts and
   parses its clap CLI).

This is the **real runtime validation**: it does NOT require the operator to own
a Mac or a Windows host.

### How to read the matrix

In the **Actions** tab → `agent-ci` run, three jobs appear:
`agent (ubuntu-latest)`, `agent (windows-latest)`, `agent (macos-latest)`.

- **All 3 green** = the agent compiles, its tests pass and the binary starts on
  all three OSes.
- **Red only on `windows-latest`** = regression in the Event Log FFI or the SCM
  (code visible only from that runner).
- **Red only on `macos-latest`** = regression in the unified-log reader / launchd.
- `fail-fast: false`: one red OS does not cancel the others → you see at once
  which OSes break.

Each job publishes the native binary as an artifact (`plume-agent-<OS>`).

### Linux-only companion: `agent-cross.yml`

[`.github/workflows/agent-cross.yml`](../.github/workflows/agent-cross.yml)
gives a contributor **without a Mac or Windows** a cross-CHECK from Linux:
`make cross-check-win` (cargo-xwin, MSVC), `make cross-check-win-fim-native`
(same target, with the `fim_windows_native` feature enabled — the
`ReadDirectoryChangesW` FIM backend only exists for the compiler under that feature,
no other job compiles it) and `make cross-check-mac` (cargo-zigbuild + zig,
darwin). It **compiles/links** the cfg-gated Win/Mac code but does **not run** it —
runtime validation remains the `agent-ci` matrix. The guard
`.github/scripts/check_every_feature_is_compiled_somewhere.py` (`shell` job of
`ci.yml`) requires every feature declared in a `Cargo.toml` to be enabled
by at least one blocking cargo command in a workflow.

## Test assumptions about the CI host (what could fail on a bare runner)

The tests were written to run on a **pristine** runner, with no privilege and no
service. Points to watch:

- **Parsing of hard-coded strings**: the Windows tests (`winxml_to_event`) and macOS
  tests (unified-log mapping) operate on **inline** XML/JSON fragments → they
  run on all 3 OSes and **never** read the real Event Log / journal.
- **No access to the real journal/Event Log required**: on a non-native target,
  `next_batch()` is a no-op (no FFI); on the native target the FFI is not
  exercised by the tests (only compiled/linked).
- **Disk I/O via `std::env::temp_dir()`** (`buffer`/`ship` tests): writable
  on all 3 runners (incl. `C:\Users\...\AppData\Local\Temp` on Windows).
- **`test-ship` EXCLUDED from CI**: it loads a config file and POSTs to an
  ingest endpoint → requires config + **network**. The CI smoke is therefore limited to
  `--version` / `--help`. For a network integration test, target a local HTTP stub
  in a future dedicated job (not required today).
- **No service installed**: the tests call neither `systemctl`, nor
  `launchctl`, nor the SCM — service installation is not exercised in CI.

## Locally

```sh
cd agent
make            # native release build (Linux)
make test       # native cargo test
# cross-check from Linux (requires cargo-xwin / cargo-zigbuild + zig):
make cross-check-win
make cross-check-win-fim-native   # + feature fim_windows_native (Windows FIM backend)
make cross-check-mac
```
