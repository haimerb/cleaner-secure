# AGENTS.md

## Project

- Windows C17 process/service scanner: CLI + Win32 GUI, no external runtime deps. Remote repo is `cleaner-secure`; binaries keep legacy `cleaner-c*` names.
- Not a git repository; do not assume git history or CI exists.
- No lint/typecheck target configured; `cleaner_tests.exe` is the test suite.

## Toolchain

- Use portable `llvm-mingw-20261117-ucrt-x86_64` at `C:\llvm-mingw-20261117-ucrt-x86_64`.
- Do not use Ninja; it is not installed. Use `MinGW Makefiles`.
- MSVC/Windows SDK + winget LLVM path fails here with missing `excpt.h`; do not switch toolchains.
- Always set PATH first in bash:
  - `export PATH="/c/llvm-mingw-20261117-ucrt-x86_64/bin:$PATH"`

## Build

- Configure once:
  - `cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-llvm-mingw.cmake -DCMAKE_MAKE_PROGRAM="/c/llvm-mingw-20261117-ucrt-x86_64/bin/mingw32-make.exe" -G "MinGW Makefiles"`
- Build:
  - `cmake --build build`
- Outputs in `build/`: `cleaner_core` (static lib), `cleaner-c-cli.exe`, `cleaner-c.exe`, `cleaner_tests.exe`.
- CMake copies only `config/iocs.json`, `config/publishers.json`, `config/thresholds.json` into `build/config/`; `config/local.json` is never copied.

## Test

- `ctest --test-dir build --output-on-failure`
- Or direct: `cd build && ./cleaner_tests.exe`
- Verified tests cover JSON parsing/accessors/UTF-8, IOC/publisher matching, response denylist, and config defaults.

## Run

- CLI once: `cd build && ./cleaner-c-cli.exe --once`
- CLI continuous: `./cleaner-c-cli.exe --interval 2`
- CLI JSON: `./cleaner-c-cli.exe --json`
- CLI actions: `--kill <pid>`, `--suspend <pid>`, `--resume <pid>`, `--service-stop <name>`, `--service-start <name>`
- GUI: `./cleaner-c.exe`
- Config is loaded from the executable directory: `build/config/`.

## Secrets

- VirusTotal key comes from `VT_API_KEY` or optional gitignored `config/local.json`.
- Never commit or copy `config/local.json`; CMake intentionally excludes it.
- CLI prints only `VirusTotal: enabled|disabled`, never the key.

## Detection quirks

- Catalog-signed system binaries can return `TRUST_E_NOSIGNATURE` to `WinVerifyTrust`; unsigned alerts are suppressed for protected dirs (`\Windows\`, `\Program Files`, `\ProgramData\Microsoft\`) but still active for user-writable paths.
- VT results are cached in memory only; no `%TEMP%` disk cache is used.
- Response actions revalidate PID image path and deny self, PID 0/4, core system images, and critical services.
- Resource IO alerts use cumulative IO counters; long-running apps may appear as medium alerts.
- `scan_timeout_ms` in `config/thresholds.json` bounds each scan pass; default 60000. Values <=30000 starve registry/Event Log on first `--once` because signature checks are slow.
- Response actions are audited to `%LOCALAPPDATA%\cleaner-c\actions.log`.
