# Offensive Nim Patterns

## Manual FFI (no winim)

Prefer when minimizing imports or learning APIs. Use `dynlib` + `stdcall`/`cdecl`:

```nim
type
  HANDLE* = int
  HWND* = HANDLE
  UINT* = int32
  LPCSTR* = cstring

proc MessageBox*(hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT): int32
  {.discardable, stdcall, dynlib: "user32", importc: "MessageBoxA".}
```

## winim Imports

| Import | Use when |
|--------|----------|
| `winim/lean` | Core Win32 — smallest footprint (~2-4 KB overhead) |
| `winim` | Full Win32 |
| `winim/com` | COM objects (+~20 KB) |

**Pitfall**: Pass `NULL` from winim, not Nim's `nil`, for WinAPI null handles.

## Byte Arrays (shellcode)

```nim
# C#: byte[] buf = { 0xfc, 0x48, ... }
var buf: array[N, byte] = [byte 0xfc, 0x48, 0x81, ...]
# First element MUST be typed: [byte ...]
```

## Embedding C/C++ in Nim

```nim
{.passC: "-I./include".}
{.compile: "helper.c".}   # or .cpp

proc externalFunc(): void {.importc.}
```

See `scshell_c_embed_bin.nim`, `clr_host_cpp_embed_bin.nim`, `unhookc.nim`.

Convert C → Nim with c2nim: `c2nim input.h -o output.nim`

## Inline Assembly (x64 syscalls, TEB)

```nim
{.passC:"-masm=intel".}

proc GetTEBAsm64(): LPVOID {.asmNoStackFrame.} =
  asm """
    push rbx
    mov rbx, qword ptr gs:[0x30]
    mov rax, rbx
    pop rbx
    ret
  """
```

## File Handles on Windows

```nim
let fh = getOsFileHandle(open("C:\\path\\file.dll", fmRead))
# NOT f.getFileHandle() — wrong on Windows
```

## HTTP / Networking

- `httpclient` stdlib for simple requests (`http_request_bin.nim`)
- `jester` for lightweight HTTP servers
- `ws` for WebSocket C2 primitives

## Crypto

```nim
import nimcrypto
import nimcrypto/sysrand
# AES-256-CTR — see encrypt_decrypt_bin.nim
```

## Resource Embedding

Compile-time embed via `staticRead` or zippy for archives (`embed_rsrc_bin.nim`).

## Opsec Notes

1. **Dynamic DLL resolution**: Nim FFI uses `LoadLibrary` — functions won't appear in static imports (good for evasion, bad for static analysis of intent).
2. **NimMain export**: DLLs always export `NimMain` — potential YARA/signature target.
3. **Nim runtime**: Heavily signatured; consider nim-less builds for mature engagements.
4. **Debug builds**: OffensiveNim Makefile defaults to `-d=debug` — never ship debug binaries to targets.

## Red Team Libraries (beyond OffensiveNim)

| Library | Purpose |
|---------|---------|
| `winim` | Windows API + COM |
| `nimcrypto` | Crypto primitives |
| `zippy` | Compression |
| `def-/nim-syscall` | Syscall helpers |
| `nimpy` | Python interop (memory-load Python DLL?) |
| `jnim` | JVM interop |
| `jester` | HTTP server |
| `nim-libp2p` | P2P networking |
| `nim-daemon` | Unix daemonization |
| `miere43/nim-registry` | Windows registry |

## Ecosystem References

- Nimplant (Mythic agent): https://github.com/MythicAgents/Nimplant
- Nim-SMBExec: https://github.com/elddy/Nim-SMBExec
- NimScan: https://github.com/elddy/NimScan
- c2nim: https://github.com/nim-lang/c2nim
- Nim FFI manual: https://nim-lang.org/docs/manual.html#foreign-function-interface