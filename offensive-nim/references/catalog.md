# OffensiveNim Example Catalog

Example sources: https://github.com/crpr777/OffensiveNim (fork of https://github.com/byt3bl33d3r/OffensiveNim). They are not vendored in this skill folder.

Use this index to find the closest working reference before writing new code. Read the source file first, then adapt — do not cargo-cult copy shellcode or hardcoded paths.

## Naming Convention

| Suffix | Output | Compile flags |
|--------|--------|---------------|
| `*_bin.nim` | Console EXE | `--app=console` |
| `*_lib.nim` | Windows DLL | `--app=lib --nomain` |

## By Category

### Windows API / FFI Basics
| File | Technique |
|------|-----------|
| `pop_bin.nim` | Manual `dynlib` FFI without winim |
| `pop_winim_bin.nim` | winim/lean MessageBox |
| `pop_winim_lib.nim` | Exported DllMain DLL |
| `stack_string_allocation.nim` | Stack-allocated C/wide strings |

### Shellcode Execution
| File | Technique |
|------|-----------|
| `shellcode_bin.nim` | CreateRemoteThread + compile-time arch (`i386`/`amd64`) |
| `shellcode_callback_bin.nim` | Callback-based execution |
| `shellcode_fiber.nim` | Fiber execution |
| `shellcode_inline_asm_bin.nim` | Inline assembly |
| `suspended_thread_injection.nim` | Suspended thread injection |
| `dynamic_shellcode_local_inject_bin.nim` | Runtime shellcode (not hardcoded) |
| `uuid_exec_bin.nim` | UUID array → heap → EnumSystemLocalesA callback |
| `rsrc_section_shellcode.nim` | Shellcode in .rsrc section |
| `taskbar_ewmi_bin.nim` | Extra Window Memory Injection via TaskBar |

### Process / Injection / Evasion
| File | Technique |
|------|-----------|
| `blockdlls_acg_ppid_spoof_bin.nim` | PPID spoof + BlockDLLs + ACG |
| `sandbox_process_bin.nim` | Untrusted integrity sandbox (disable PPL) |
| `local_pe_execution.nim` | In-memory PE/DLL execution |
| `unhook.nim` | Pure Nim ntdll unhook |
| `unhookc.nim` | Embedded C unhook template |
| `amsi_patch_bin.nim` | AMSI patch (current process) |
| `amsi_providerpatch_bin.nim` | AMSI provider DLL patch |
| `etw_patch_bin.nim` | ETW patch |
| `syscalls_bin.nim` | Direct syscalls / TEB via inline asm |
| `ssdt_dump.nim` | SSDT via exception directory |
| `syscall_process_enum.nim` | Syscall-based process enum |

### Credential / Token / Dump
| File | Technique |
|------|-----------|
| `minidump_bin.nim` | MiniDumpWriteDump on lsass |
| `fork_dump_bin.nim` | Windows fork() + MiniDumpWriteDump |
| `token_steal_cmd.nim` | Token steal + impersonate + run cmd |
| `chrome_dump_bin.nim` | Chrome cookie DB decrypt |
| `passfilter_lib.nim` | Password filter DLL (credential logging) |

### .NET / COM / Scripting
| File | Technique |
|------|-----------|
| `execute_assembly_bin.nim` | CLR host, in-memory .NET assembly |
| `clr_host_cpp_embed_bin.nim` | Embedded C++ CLR host |
| `execute_powershell_bin.nim` | CLR + unmanaged PowerShell runspace |
| `execute_sct_bin.nim` | .sct via GetObject() |
| `scriptcontrol_bin.nim` | MSScriptControl VBScript/JScript |
| `excel_com_bin.nim` | Excel COM macro shellcode injection |
| `out_compressed_dll_bin.nim` | Compress + b64 PowerShell DLL loader |

### Recon / Enumeration
| File | Technique |
|------|-----------|
| `wmiquery_bin.nim` | WMI process/AV enumeration |
| `fltmc_bin.nim` | Minifilter driver enumeration |
| `ldap_query_bin.nim` | LDAP via ADO ADSI COM |
| `list_remote_shares.nim` | NetShareEnum |
| `http_request_bin.nim` | HTTP client patterns |

### IPC / C2 Primitives
| File | Technique |
|------|-----------|
| `named_pipe_client_bin.nim` | Named pipe client |
| `named_pipe_server_bin.nim` | Named pipe server |
| `dns_exfiltrate.nim` | DNS TXT exfiltration |

### Linux / Cross-Platform
| File | Technique |
|------|-----------|
| `memfd_python_interpreter_bin.nim` | memfd_create + execve (Linux) |
| `dns_exfiltrate.nim` | DNS (portable) |
| `encrypt_decrypt_bin.nim` | AES-256-CTR via nimcrypto (portable) |

### Anti-Analysis
| File | Technique |
|------|-----------|
| `anti_analysis_isdebuggerpresent.nim` | IsDebuggerPresent check |
| `anti_debug.nim` | Multiple anti-debug techniques |
| `anti_debug_via_tls.nim` | TLS-based anti-debug |
| `sandbox_domain_check.nim` | Domain-joined check |
| `hardware_breakpoints.nim` | HW breakpoint hooking |
| `Hook.nim` | API hooking (MessageBoxA) |

### Embedding / Resources / Opsec
| File | Technique |
|------|-----------|
| `embed_rsrc_bin.nim` | Compile-time zip embed + extract |
| `self_delete_bin.nim` | Delete locked/running executable |
| `encrypt_decrypt_bin.nim` | AES-256-CTR encryption |
| `scshell_c_embed_bin.nim` | Embed existing C code (SCShell) |

### WIP (do not treat as production-ready)
| File | Status |
|------|--------|
| `wip/amsi_patch_2_bin.nim` | Alternate AMSI patch — incomplete |
| `wip/excel_4_com_bin.nim` | Excel 4 macros — incomplete |