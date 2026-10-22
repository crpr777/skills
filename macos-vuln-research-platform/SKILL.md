---
name: macos-vuln-research
description: >
  Guide for macOS and Apple platform vulnerability research, exploit development,
  and offensive security analysis. Use this skill whenever the user asks about macOS
  kernel or userland vulnerability research, XNU internals, IOKit driver auditing,
  Mach IPC attack surface, macOS sandbox escapes, TCC bypass research, Apple Silicon
  security boundaries, dyld/DYLD_* injection, Objective-C/Swift runtime exploitation,
  macOS malware analysis, red team tradecraft on macOS endpoints, macOS entitlement
  and code-signing abuse, fuzzing macOS targets (AFL++, libFuzzer, hongfuzz), KEXT
  or DriverKit auditing, or building a macOS/iOS vulnerability research lab. Also
  trigger when the user mentions CVE analysis on Apple platforms, writing proof-of-concept
  exploits for macOS, CVSS scoring for macOS findings, or reversing macOS binaries
  with Ghidra/IDA/Hopper. This skill covers the full lifecycle from target selection
  through root cause analysis, PoC development, and responsible disclosure.
---

# macOS Vulnerability Research

A structured reference for conducting macOS and Apple platform vulnerability research,
covering environment setup, target identification, analysis methodology, exploit
development, and disclosure workflow.

## How to Use This Skill

1. **Start here** for workflow guidance, methodology, and quick-reference commands.
2. **Read `references/xnu-internals.md`** when working on kernel-level research
   (Mach IPC, IOKit, kexts, MACF, sandbox kernel extensions).
3. **Read `references/userland-attack-surface.md`** when targeting userland daemons,
   frameworks, IPC services (XPC, NSXPCConnection), or privilege boundaries
   (TCC, Authorization Services, endpointd).
4. **Read `references/tooling-lab-setup.md`** when setting up or upgrading your
   research environment (VMs, debuggers, fuzzers, jailbroken devices).

---

## Research Methodology Overview

### Phase 1: Target Selection and Scoping

Identify high-value attack surface based on your research goals:

**Kernel Attack Surface (XNU / IOKit / KEXT / DriverKit)**
- IOKit user clients reachable from app sandbox (enumerate with `ioreg` and
  `IOServiceGetMatchingServices`)
- Mach IPC services exposed via `bootstrap_look_up` (audit with `launchctl list`,
  `lsmp`)
- Filesystem drivers (APFS, FAT, exFAT, SMB) triggered by mounting crafted images
- Network stack (TCP/IP, Bluetooth, Wi-Fi 802.11) for remote/proximity attack surface
- MACF policy hooks and sandbox profile enforcement gaps
- Kernel extensions in `/Library/Extensions` and `/System/Library/Extensions`

**Userland Attack Surface**
- XPC services (enumerate via `launchctl list`, inspect plists in
  `/System/Library/LaunchDaemons` and `LaunchAgents`)
- Privileged helper tools installed via `SMJobBless`
- IPC via Mach messages, distributed notifications, pasteboard
- URL scheme handlers and universal links (abuse via `lsregister -dump`)
- Accessibility and Input Method frameworks
- Third-party kernel extensions and system extensions (Network Extension,
  Endpoint Security)

**Privacy / Permissions (TCC) Attack Surface**
- TCC.db manipulation and reset vectors
- Consent prompt bypass via bundle injection or app impersonation
- Full Disk Access, Screen Recording, Accessibility, Automation entitlement abuse
- MDM profile injection for silent permission grants

**Supply Chain and Code Signing**
- Entitlement analysis (`codesign -d --entitlements - <binary>`)
- Provisioning profile and Team ID trust chain weaknesses
- Notarization bypass and Gatekeeper circumvention (quarantine attribute removal)
- dylib hijacking in signed bundles with `@rpath` / `@loader_path`

### Phase 2: Reconnaissance and Attack Surface Mapping

```bash
# --- System Enumeration ---
sw_vers                                   # macOS version
sysctl hw.machine hw.cpu64bit_capable     # Architecture
csrutil status                            # SIP status
nvram -p | grep -i boot                   # Boot args (check for debug flags)

# --- Kernel Info ---
uname -a
kextstat | grep -v com.apple              # Third-party kexts
kmutil showloaded --list-only             # Big Sur+ kernel collection

# --- Service Enumeration ---
launchctl list                            # Running services
launchctl print system                    # System domain detail
find /System/Library/LaunchDaemons -name "*.plist" | head -30

# --- XPC Service Discovery ---
# Find XPC service bundles
find /System/Library -name "*.xpc" -type d 2>/dev/null | head -20

# --- Entitlement Audit ---
# Dump entitlements for all binaries in a directory
find /usr/libexec -type f -perm +111 | while read bin; do
  ents=$(codesign -d --entitlements - "$bin" 2>/dev/null)
  if echo "$ents" | grep -q "com.apple.private"; then
    echo "=== $bin ==="
    echo "$ents" | head -20
  fi
done

# --- IPC Surface ---
lsmp -p <pid>                            # Mach port listing for a process
launchctl print system/<service-label>    # Service details

# --- TCC Database (read only, SIP protected) ---
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, allowed FROM access;"

# --- Mach-O Binary Analysis ---
otool -L <binary>                         # Linked libraries
otool -l <binary> | grep -A2 LC_RPATH     # RPATH entries (dylib hijack candidates)
nm -m <binary> | grep " _objc_msgSend"    # ObjC method dispatch
class-dump <binary> > headers.h           # ObjC class/protocol extraction
```

### Phase 3: Vulnerability Analysis Techniques

**Static Analysis Workflow**
1. Obtain target binary (extract from IPSW, copy from running system, or pull
   from dyld shared cache via `dyld_shared_cache_util`)
2. Load into disassembler (Ghidra, IDA, Hopper)
3. Identify input handling: file parsers, network protocol handlers, IPC message
   deserializers, IOKit `externalMethod` dispatch tables
4. Trace data flow from input to sensitive operations (memory allocation,
   `copyin`/`copyout`, `IOMemoryDescriptor` creation, `vm_map` calls)
5. Look for classic vulnerability classes:
   - Integer overflows in size calculations before allocation
   - Type confusion in ObjC/Swift deserialization or IOKit method dispatch
   - Use-after-free in reference counting (retain/release) patterns
   - Race conditions in TOCTOU checks (file operations, IPC validation)
   - Format string bugs in logging paths
   - Heap buffer overflows in binary format parsers
   - Logic bugs in authorization/entitlement checks

**Dynamic Analysis Workflow**
1. Instrument target with DTrace, `dtrace -n 'syscall::*:entry /execname == "target"/ {}'`
2. Attach lldb for interactive debugging (kernel debug via two-machine setup or
   `DEVELOPMENT` kernel on VM)
3. Use Frida for runtime hooking of ObjC/Swift methods:
   ```javascript
   // Frida script: hook an XPC connection handler
   const handler = ObjC.classes.MyXPCService['- listener:shouldAcceptNewConnection:'];
   Interceptor.attach(handler.implementation, {
     onEnter(args) {
       console.log('XPC connection from:', ObjC.Object(args[3]));
     }
   });
   ```
4. Enable sanitizers for test builds:
   `ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 ./target`
5. Monitor with Instruments (Allocations, Leaks, System Trace) for heap state

**Fuzzing Strategy**
- **Coverage-guided**: AFL++ or libFuzzer against userland parsers (images, fonts,
  plists, archives). Build with `clang -fsanitize=fuzzer,address`.
- **Structure-aware**: Write custom mutators for binary formats (Mach-O, DMG,
  APFS structures) using protobuf-based grammar fuzzing (libprotobuf-mutator).
- **Kernel fuzzing**: Use a patched DEVELOPMENT kernel on a VM with
  `boot-args="debug=0x44 kcsuffix=development"`. Fuzzing via IOKit user client
  calls (`IOConnectCallMethod`) or crafted filesystem images.
- **Network fuzzing**: Proxy-based fuzzing of AirDrop (AWDL), Bluetooth (IOBluetooth),
  or mDNS/Bonjour with boofuzz or custom tooling.
- **Crash triage**: Use `CrashWrangler` or parse crash logs from
  `~/Library/Logs/DiagnosticReports/`. Bucket by faulting instruction, stack hash,
  and crash type. Deduplicate before deep analysis.

### Phase 4: Root Cause Analysis

Once a crash or unexpected behavior is identified:

1. **Reproduce reliably** -- minimize the test case (`afl-tmin` or manual reduction)
2. **Determine crash type** -- read `Exception Type` and `Exception Codes` from
   crash log. Map `EXC_BAD_ACCESS (SIGBUS/SIGSEGV)` to read/write/exec, check
   `EXC_BAD_INSTRUCTION` for sanitizer-detected issues.
3. **Identify the vulnerable code path** -- walk the stack trace back to the input
   handler. Cross-reference with disassembly.
4. **Classify the vulnerability** -- map to CWE (e.g., CWE-122 heap overflow,
   CWE-416 use-after-free, CWE-190 integer overflow). Determine CVSS 3.1 vector
   string, paying attention to:
   - Attack Vector (Network vs Local vs Physical)
   - Attack Complexity (is winning a race required?)
   - Privileges Required (sandbox, root, kernel)
   - User Interaction (does victim need to open a file?)
   - Scope (does kernel vuln escape sandbox? TCC bypass escalate scope?)
5. **Assess exploitability** -- consider ASLR (KASLR for kernel), PAC (pointer
   authentication on Apple Silicon), PPL (Page Protection Layer), KTRR/AMCC
   (kernel text readonly region), zone/kalloc bucket isolation, and sandboxing.

### Phase 5: Proof-of-Concept Development

**PoC Best Practices**
- Write a self-contained PoC that demonstrates the vulnerability without
  weaponized payloads. Goal: crash, info leak, or permission bypass demonstration.
- Target the most recent affected macOS version.
- Document exact reproduction steps, required entitlements, and system state.
- Include a `Makefile` or build script with compiler flags.
- For IOKit bugs, use `IOServiceOpen` / `IOConnectCallMethod` C harness.
- For XPC bugs, create a minimal client with `NSXPCConnection`.
- For kernel bugs on Apple Silicon, account for PAC and MTE implications.

**PoC File Structure**
```
CVE-YYYY-NNNNN/
├── README.md              # Vulnerability description, affected versions, CVSS
├── poc.c (or poc.m/py)    # Minimal reproduction
├── Makefile
├── crash_log.txt          # Representative crash
└── analysis/
    ├── root_cause.md      # Detailed technical analysis
    └── screenshots/       # Proof screenshots/recordings
```

### Phase 6: Disclosure

**Apple Security Bounty Program**
- Submit via https://developer.apple.com/security-bounty/
- Include: description, affected versions, PoC, impact assessment
- Apple typically responds within 5 business days for initial acknowledgment
- Coordinate disclosure timeline (Apple generally requests 90 days)
- Track your submission; follow up at 30 and 60 days if no substantive response

**Alternative Coordinated Disclosure**
- CERT/CC (for multi-vendor issues)
- Zero Day Initiative (ZDI) for brokered disclosure + bounty
- Direct vendor contact for third-party macOS software

**CVSS 3.1 Scoring Reference (macOS-Specific Considerations)**
- Local privilege escalation (user to root): typical AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8
- Sandbox escape: consider Scope Changed (S:C) if crossing trust boundary
- Kernel code execution from app: AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 9.3 (if no user interaction)
- Remote code execution via network service: AV:N, adjust AC based on whether
  ASLR defeat is required
- TCC bypass: typically C:H with S:U or S:C depending on scope of accessed data
- For physical security findings in red team context, see CVSS guidance in
  `references/tooling-lab-setup.md`

---

## Quick Reference: Key macOS Security Boundaries

| Boundary              | Enforced By                        | Bypass = ?                    |
|-----------------------|------------------------------------|-------------------------------|
| App Sandbox           | Sandbox.kext + profiles            | Sandbox escape                |
| SIP (rootless)        | Kernel (AMFI + mount policy)       | SIP bypass (critical)         |
| TCC (privacy)         | tccd + TCC.db                      | TCC bypass                    |
| AMFI                  | Kernel (code signing enforcement)  | Code signing bypass           |
| Gatekeeper            | LaunchServices + quarantine xattr  | Gatekeeper bypass             |
| KASLR                 | Kernel (random base address)       | Kernel info leak              |
| PAC                   | Hardware (Apple Silicon)           | PAC bypass / signing gadget   |
| PPL                   | Hardware (Apple Silicon)           | PPL bypass (very high value)  |
| KTRR / AMCC           | Hardware (kernel text RO)          | Integrity bypass              |
| Secure Boot chain     | Hardware (SEP + iBoot)             | Bootchain exploit             |

---

## Common Tool Commands Quick Reference

```bash
# --- Disassembly / RE ---
# Extract binary from dyld shared cache (Ventura+)
dyld_shared_cache_util -extract /tmp/extracted /System/Volumes/Preboot/*/...

# Ghidra headless analysis
analyzeHeadless /tmp/ghidra_project MyProject -import /path/to/binary \
  -postScript ExportFunctions.java -scriptPath /path/to/scripts

# class-dump for ObjC headers
class-dump -H -o /tmp/headers /path/to/framework

# --- Debugging ---
# Kernel debugging (two-machine setup)
# On target: nvram boot-args="debug=0x44 kdp_match_name=en0 -v"
# On host:   lldb -o "kdp-remote <target-ip>"

# Userland debugging with entitlements
lldb --attach-pid $(pgrep targetd)
# or: debugserver *:1234 --attach=<pid>  (from Xcode)

# --- Frida ---
frida -U -n "Safari" -l hook.js           # Attach to process
frida-trace -U -n "Safari" -m "-[NSURL *]" # Trace ObjC methods

# --- DTrace ---
# Trace file opens by a specific process
dtrace -n 'syscall::open*:entry /execname == "target"/ { printf("%s", copyinstr(arg0)); }'

# Trace Mach message sends
dtrace -n 'mach_trap::mach_msg_trap:entry /execname == "target"/ { stack(); }'

# --- Crash Log Parsing ---
# Parse and symbolicate
atos -o /path/to/binary -arch arm64 -l 0xloadaddr 0xcrashaddr
# or use: /usr/bin/sample <pid> 5   for live stack sampling

# --- Fuzzing ---
# AFL++ (compile target first)
afl-clang-fast -fsanitize=address -o target_fuzz target.c
afl-fuzz -i corpus/ -o findings/ -- ./target_fuzz @@

# libFuzzer
clang -fsanitize=fuzzer,address -o fuzz_target harness.c target.c
./fuzz_target corpus/ -max_total_time=3600
```

---

## Apple Platform Version Research Notes

When researching vulnerabilities, always check:
- Which macOS versions are affected (map to XNU / Darwin kernel versions)
- Whether the issue exists on iOS/iPadOS/watchOS/tvOS (shared XNU base)
- Whether Apple Silicon mitigations (PAC, MTE, PPL) affect exploitability
- Whether SIP/SSV (Signed System Volume) prevents persistence
- The `Security Update` release notes for prior art: https://support.apple.com/en-us/100100

**Version Mapping (keep updated)**
- Use `sw_vers` and `uname -r` to get exact build/Darwin version
- Cross-reference with https://opensource.apple.com/releases/ for source availability
- Track security fixes in Apple's CVE database for collision avoidance

---

## Integration with Red Team Operations

When macOS vuln research feeds into a red team engagement:

1. **Initial Access**: Exploit Gatekeeper/quarantine bypass or weaponized document
   with macOS-specific payload (JXA, AppleScript, dylib sideload)
2. **Execution**: JXA (JavaScript for Automation), osascript, Python/Swift payloads,
   dylib injection via DYLD_INSERT_LIBRARIES (blocked by Hardened Runtime unless
   entitlement present)
3. **Persistence**: LaunchAgent/LaunchDaemon, login items, cron, directory services
   plugin, authorization plugin, kernel extension (pre-Ventura)
4. **Privilege Escalation**: Exploit local vuln, abuse sudo misconfiguration, exploit
   `suid` binaries, AuthorizationExecuteWithPrivileges abuse, CVE-based escalation
5. **Defense Evasion**: TCC bypass, SIP-aware operations, in-memory execution,
   dyld interposing, code-cave injection in signed binaries (resign with ad-hoc)
6. **Collection**: Keychain dump (`security dump-keychain`), TCC-protected data
   access via bypass, clipboard monitoring, screen capture via CGWindowListCreateImage

Map all findings to MITRE ATT&CK for macOS (T1059.002 AppleScript, T1059.007 JXA,
T1547.011 LaunchAgent, T1548.004 Elevated Execution, etc.).
