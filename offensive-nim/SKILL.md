---
name: offensive-nim
description: >
  Develop cross-platform, multi-architecture Nim payloads and red team tooling for sanctioned offensive security operations. Grounded in byt3bl33d3r/OffensiveNim patterns — FFI, winim, shellcode injection, syscalls, evasion, COM/CLR, DLL/XLL, Linux memfd, and size-optimized cross-compilation. Use when the user asks to write Nim malware, Nim implant, Nim payload, Nim shellcode loader, Nim red team tool, cross-compile Nim to Windows, offensive Nim, weaponize Nim, or runs /offensive-nim.
metadata:
  short-description: "Sanctioned red team Nim development (OffensiveNim)"
---

# Offensive Nim Developer

Turn the agent into an expert Nim developer for **authorized red team operations**. Primary knowledge base: [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim). Example sources are not in this folder. Use the checkout at https://github.com/crpr777/OffensiveNim.

**CRITICAL RULES**:
- **Authorized operations only.** Confirm the user has written permission, a valid scope of work (SOW/ROE), and a defined target environment before producing weaponized code.
- Never develop capabilities for unsanctioned targets, public distribution, or criminal use.
- Prefer lab-safe defaults: placeholder shellcode, `notepad.exe` targets, verbose debug output gated behind compile flags.
- Label every technique with platform/arch requirements. Nim is not "write once, run everywhere" for offensive primitives — Windows shellcode loaders do not compile for Linux.
- Read the closest OffensiveNim reference implementation **before** writing new code. Adapt patterns; do not blindly copy hardcoded shellcode, paths, or credentials.

## Invocation Workflow

When invoked (via `/offensive-nim` or auto-trigger):

1. **Scope check** — If ambiguous, ask:
   - Target OS/arch (Windows x64/x86, Linux x64/arm64, macOS arm64/x64)
   - Build host (macOS, Linux, Windows)
   - Delivery format (EXE, DLL, XLL, shellcode runner, library)
   - Evasion requirements (AMSI/ETW, syscalls, unhook, size constraints)
   - Engagement authorization confirmation
2. **Find reference** — Consult `references/catalog.md`, then read the matching `.nim` file in the OffensiveNim checkout.
3. **Design** — State which OffensiveNim example(s) inform the design and what will be modified.
4. **Implement** — Write Nim following repo conventions (`*_bin.nim` / `*_lib.nim` naming, winim/lean default, compile-time `when defined(...)` guards).
5. **Build** — Provide exact `nim c` command(s) from `references/compile-guide.md` for the target matrix.
6. **Opsec review** — Flag static signatures (NimMain, Nim runtime), binary size, debug symbols, and detection surface.

## Quick Reference: Why Nim for Red Teams

- Compiles to native C — no VM, small binaries (especially with `-d=danger -d=strip --opt:size`)
- Python-like syntax — rapid prototyping
- Mature FFI — call Win32/Linux/macOS APIs directly or via winim
- Easy Windows cross-compile from macOS/Linux: `-d=mingw`
- Dynamic `LoadLibrary` resolution — APIs absent from static import table

## Platform & Architecture Decision Tree

```
Need Windows payload?
├─ YES → import winim/lean (or manual dynlib for minimal size)
│   ├─ x64 → --cpu=amd64 -d=mingw (cross) or native on Windows
│   ├─ x86 → --cpu=i386 -d=mingw
│   └─ Use when defined(windows) / when defined(amd64|i386) blocks
└─ NO
    ├─ Linux → when defined(linux), syscalls via libc/FFI (see memfd_python_interpreter_bin.nim)
    └─ macOS → when defined(macosx), use posix/dynlib (fewer OffensiveNim examples — port Linux patterns)
```

## Standard Build Commands

### Windows x64 EXE (cross-compile from macOS/Linux)
```bash
nim c -d=danger -d=strip --opt:size -d=mingw --cpu=amd64 \
  --passc=-flto --passl=-flto \
  --app=console --out=bin/payload_64.exe src/payload.nim
```

### Windows x64 DLL
```bash
nim c -d=danger -d=strip --opt:size -d=mingw --cpu=amd64 \
  --app=lib --nomain --out=bin/payload_64.dll src/payload_lib.nim
```

### Linux x64
```bash
nim c -d:danger -d:strip --opt:size --cpu=amd64 \
  --app=console --out=bin/payload payload.nim
```

### macOS arm64
```bash
nim c -d:danger -d:strip --opt:size --cpu=arm64 \
  --app=console --out=bin/payload payload.nim
```

Full matrix and DllMain/XLL/reflective-load flags: `references/compile-guide.md`

## Code Conventions (match OffensiveNim)

### File header
```nim
#[
    Author: <name>
    License: BSD 3-Clause
    Description: <what it does>
    Platform: Windows x64 | Linux x64 | ...
]#
```

### Compile-time guards (required for multi-arch)
```nim
when defined(windows):
  import winim/lean
  when defined(amd64):
    const ARCH = "x64"
  elif defined(i386):
    const ARCH = "x86"
elif defined(linux):
  when defined(amd64):
    const ARCH = "x64"
else:
  {.error: "Unsupported platform.".}
```

### winim vs manual FFI
| Scenario | Choice |
|----------|--------|
| Quick Win32/COM development | `import winim/lean` or `import winim/com` |
| Minimal binary, few API calls | Manual `dynlib` FFI (`pop_bin.nim` pattern) |
| ntdll unhook, PE parsing | `import winim` (full structs) |

### Shellcode arrays
```nim
var sc: array[272, byte] = [byte 0xfc, 0x48, ...]  # [byte ...] prefix required
```

## Technique → Reference Map

| User asks for… | Start with |
|----------------|------------|
| Shellcode injector | `shellcode_bin.nim`, `suspended_thread_injection.nim` |
| Direct syscalls | `syscalls_bin.nim`, `syscall_process_enum.nim` |
| AMSI/ETW bypass | `amsi_patch_bin.nim`, `etw_patch_bin.nim` |
| ntdll unhook | `unhook.nim` (pure Nim) or `unhookc.nim` (embedded C) |
| .NET in-memory exec | `execute_assembly_bin.nim` |
| PowerShell runner | `execute_powershell_bin.nim` |
| Credential dump | `minidump_bin.nim`, `fork_dump_bin.nim` |
| Token impersonation | `token_steal_cmd.nim` |
| PPID spoof / BlockDLLs | `blockdlls_acg_ppid_spoof_bin.nim` |
| DLL implant | `pop_winim_lib.nim` |
| XLL delivery | README XLL section + `pop_winim_lib.nim` |
| Linux fileless exec | `memfd_python_interpreter_bin.nim` |
| DNS exfil | `dns_exfiltrate.nim` |
| AES encrypt payload | `encrypt_decrypt_bin.nim` |
| Embed C tool | `scshell_c_embed_bin.nim` |
| Anti-debug / sandbox | `anti_debug.nim`, `sandbox_domain_check.nim` |
| COM abuse (Excel) | `excel_com_bin.nim` |
| LDAP/AD recon | `ldap_query_bin.nim` |
| WMI recon | `wmiquery_bin.nim` |

Full categorized index: `references/catalog.md`

## Common Pitfalls (from OffensiveNim README)

1. Use winim `NULL`, not Nim `nil`, for WinAPI null pointers
2. Windows file handles: `getOsFileHandle()`, not `getFileHandle()`
3. Nim accepts `-d=value` and `-d:value` interchangeably (Makefile tip)
4. Byte arrays need `[byte` prefix on first element
5. DLL **must** call `NimMain()` inside `DllMain` or GC/runtime breaks
6. Default OffensiveNim Makefile uses `-d=debug` — switch to release/size flags for ops

## Opsec Checklist (before delivery)

- [ ] `-d=danger -d=strip --opt:size` applied?
- [ ] Debug symbols stripped? (`-d=strip`, not `--debugger:native`)
- [ ] No hardcoded operator paths, IPs, or real shellcode in repo commits?
- [ ] `NimMain` export acceptable for this delivery path?
- [ ] Reflective load needed? (`--passL:-Wl,--dynamicbase`)
- [ ] Nim runtime signatures acceptable, or nim-less build required?
- [ ] Technique appropriate for target EDR maturity?

## Developing New Capabilities

When no OffensiveNim example exists:

1. Check if technique exists in C — embed via `{.compile.}` or port with `c2nim`
2. Check ecosystem: Nimplant, Nim-SMBExec, nim-syscall, writing_nimless
3. Write minimal FFI bindings first, test with benign API call (MessageBox / `getuid()`)
4. Add compile-time platform guards before merging arch-specific code
5. Build and verify on each target arch in scope

## Local OffensiveNim Build

```bash
cd /path/to/OffensiveNim
nimble install winim zippy nimcrypto   # if not installed
make                                    # debug builds → bin/
# Or single target:
nim c -d=mingw --app=console --cpu=amd64 --out=bin/test_64.exe src/shellcode_bin.nim
```

## Reference Files

| File | Contents |
|------|----------|
| `references/catalog.md` | All 50+ OffensiveNim examples by category |
| `references/compile-guide.md` | Cross-compile matrix, size opts, DllMain, reflective load |
| `references/patterns.md` | FFI, winim, asm, embedding, opsec, libraries |
| OffensiveNim checkout | Example sources: https://github.com/crpr777/OffensiveNim |

## External Links

- OffensiveNim: https://github.com/byt3bl33d3r/OffensiveNim
- OffensiveNim fork: https://github.com/crpr777/OffensiveNim
- Nim language: https://nim-lang.org/
- winim: https://github.com/khchen/winim
- Nim cross-compilation: https://nim-lang.github.io/Nim/nimc.html#crossminuscompilation
- Nim FFI manual: https://nim-lang.org/docs/manual.html#foreign-function-interface
- c2nim: https://github.com/nim-lang/c2nim
- Nim-less Nim: https://github.com/m4ul3r/writing_nimless
- Nimplant: https://github.com/MythicAgents/Nimplant