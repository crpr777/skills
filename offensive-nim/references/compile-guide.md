# Offensive Nim Compile Guide

## Toolchain Setup

```bash
# macOS
brew install nim mingw-w64
nimble install winim zippy nimcrypto

# Debian/Ubuntu
apt install nim mingw-w64
nimble install winim zippy nimcrypto

# Windows (native)
# Install from https://nim-lang.org/install_windows.html
nimble install winim zippy nimcrypto
```

OffensiveNim devcontainer: `.devcontainer/` in the OffensiveNim checkout — auto-installs choosenim + winim + c2nim.

## Cross-Compilation Matrix

| Host | Target | Key flags |
|------|--------|-------------|
| macOS/Linux | Windows x64 | `-d=mingw --cpu=amd64` |
| macOS/Linux | Windows x86 | `-d=mingw --cpu=i386` |
| macOS | macOS arm64 | `--cpu=arm64` (native) |
| macOS | macOS x64 | `--cpu=amd64` |
| Linux | Linux x64 | `--cpu=amd64` (native) |
| Linux | Linux arm64 | `--cpu=arm64` |

### Windows EXE (console)
```bash
nim c -d=mingw --app=console --cpu=amd64 --out=bin/payload_64.exe src/payload.nim
```

### Windows DLL
```bash
nim c -d=mingw --app=lib --nomain --cpu=amd64 --out=bin/payload_64.dll src/payload_lib.nim
```

### Windows XLL (Excel add-in)
```bash
nim c -d=mingw --app=lib --nomain --cpu=amd64 nim_xll.nim
# Rename output .dll → .xll
```

### Linux native
```bash
nim c -d:release --cpu=amd64 --out=bin/payload payload.nim
```

### macOS native
```bash
nim c -d:release --cpu=arm64 --out=bin/payload payload.nim   # Apple Silicon
nim c -d:release --cpu=amd64 --out=bin/payload payload.nim    # Intel Mac
```

## Size Optimization (production payloads)

```bash
nim c -d=danger -d=strip --opt:size \
  --passc=-flto --passl=-flto \
  -d=mingw --cpu=amd64 payload.nim
```

OffensiveNim reports shellcode_bin drops from ~484 KB → ~46.5 KB with these flags on macOS cross-compile.

## Reflective Loading (PE relocation table)

Nim PEs lack relocation tables by default. For reflective loaders:

```bash
nim c --passL:-Wl,--dynamicbase payload.nim
```

## Compile-Time Platform Detection

```nim
when defined(windows):
  when defined(i386):
    # x86 Windows shellcode / syscalls
  elif defined(amd64):
    # x64 Windows shellcode / syscalls
elif defined(linux):
  when defined(amd64):
    # Linux x64
elif defined(macosx):
  when defined(arm64):
    # Apple Silicon
```

Compiler-defined constants: https://github.com/nim-lang/Nim/wiki/Consts-defined-by-the-compiler

## OffensiveNim Makefile

From the OffensiveNim checkout:

```bash
make          # builds all *_bin.nim → bin/*_64.exe, *_lib.nim → bin/*_64.dll
make clean
make rebuild
```

Default `NIMFLAGS` in repo is debug mode. For ops builds, switch to:
```
NIMFLAGS = -d=danger -d=mingw -d=strip --passc=-flto --passl=-flto --opt=size
```

## DllMain Pattern (critical)

```nim
import winim/lean

proc NimMain() {.cdecl, importc.}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL
    {.stdcall, exportc, dynlib.} =
  NimMain()  # REQUIRED — initializes GC
  if fdwReason == DLL_PROCESS_ATTACH:
    discard
  return true
```

## Nim-less / Runtime-Free Builds

For AV/EDR evasion where Nim runtime signatures are flagged:
- Study: https://github.com/m4ul3r/writing_nimless
- Use winim type defs only; avoid GC, exceptions, and stdlib features that pull runtime
- See Bitmancer: https://github.com/zimawhit3/Bitmancer