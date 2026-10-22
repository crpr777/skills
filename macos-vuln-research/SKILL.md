---
name: macos-vuln-research
description: >
  Execute deep macOS vulnerability research identifying TCC bypasses, privacy framework flaws, and local privilege escalation paths for responsible disclosure to Apple's Security Bounty program and macOS hardening. Use when the user asks to research macOS TCC, hunt for macOS 0-days or bypasses, find privilege escalation, audit macOS privacy protections, prepare Apple security report, or run /macos-vuln-research or /tcc-research.
metadata:
  short-description: "Deep macOS TCC bypass & LPE research + responsible Apple reporting"
---

# macOS Vulnerability Research: TCC Bypasses & Privilege Escalation

Turn the agent into a focused macOS security researcher specializing in **Transparency, Consent, and Control (TCC)** bypasses and local privilege escalation (LPE). Primary objective: discover or validate issues, produce **complete, actionable reports** suitable for Apple's Security Bounty program at https://security.apple.com/bounty/ (and the submit portal), and deliver concrete hardening guidance.

**CRITICAL RULES**:
- Only operate on systems and accounts you fully own and control.
- **Responsible disclosure only**. Never weaponize, never publish PoCs publicly before Apple has shipped fixes or explicitly authorized.
- Prioritize safety: use a dedicated test user, snapshot/VM, or secondary Mac when possible.
- All research must aim to **improve** macOS security.

## Invocation & Workflow

When invoked (via slash or auto-trigger):
1. Confirm scope with user if ambiguous: macOS version focus, specific app/daemon, full system sweep, or "hunt anything new".
2. Run Phase 1 enumeration and present a concise baseline report.
3. Proceed through targeted phases based on findings and user direction.
4. For every potential issue: document root cause, affected builds, repro, impact, evidence (logs, tccutil flag output, screenshots).
5. At conclusion: draft a full Apple-ready report + list of hardening steps + any 3rd-party vendor reports needed.
6. Use `tccutil flag check` / Target Flags wherever possible to strengthen bounty claims.

## Phase 0: Quick Safety & Environment Check

```bash
sw_vers
csrutil status
csrutil authenticated-root status
sysctl kern.bootargs
launchctl print system/com.apple.tccd | cat
id -u
whoami
```

- Confirm SIP is enabled (default). Note if any boot args disable protections.
- Grant **Full Disk Access** to your terminal/research process in System Settings → Privacy & Security if needed for DB dumps and deep inspection.
- Prefer running research commands from a clean, low-privilege test account.

## Phase 1: Comprehensive Enumeration

Collect and save output of:

**System baseline**
- `sw_vers -productVersion -buildVersion`
- `uname -a`
- `system_profiler SPSoftwareDataType SPHardwareDataType`
- Security update status vs Apple's public list (support.apple.com/en-us/HT201222)

**TCC state (user + system)**
```bash
# User DB
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "
  SELECT service, client, client_type, auth_value, auth_reason, 
         indirect_object_identifier, flags, last_modified 
  FROM access 
  ORDER BY last_modified DESC;"
```
```bash
# System DB (often requires FDA or root)
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "
  SELECT service, client, auth_value FROM access 
  WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;"
```

**Live TCC monitoring** (run in background or separate window)
```bash
log stream --level debug --predicate 'subsystem == "com.apple.TCC"' 
# or broader
log stream --info --predicate 'eventMessage contains "TCC" or subsystem contains "tcc"'
```

**Launch items & privileged jobs**
```bash
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null
launchctl list | grep -v '^com\.apple\.' | cat
```

**SUID/SGID & interesting binaries**
```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -30
```

**Entitlements & code signing sweep** (focus on /Applications, /System/Applications, user-installed)
```bash
# Quick scan for dangerous entitlements
for d in /Applications/*.app /System/Applications/*.app "$HOME/Applications"/*.app 2>/dev/null; do
  bin=$(find "$d/Contents/MacOS" -type f -perm +111 2>/dev/null | head -1)
  [ -z "$bin" ] && continue
  echo "=== $d"
  codesign -d --entitlements :- "$bin" 2>/dev/null | grep -E 'com.apple.security|task-allow|library-validation|allow-unsigned' || true
done
```

**Other high-value**
- `spctl --status`
- `kmutil showloaded | grep -v com.apple`
- `mdfind -name '*.mdimporter' 2>/dev/null`
- `find ~/Library -name '*.dylib' -o -name '*.plugin' 2>/dev/null | head -20`
- `sudo tccutil reset` is destructive — avoid unless in test account.

## Phase 2: TCC Bypass Hunting Playbook

TCC protects services such as:
kTCCServiceSystemPolicyAllFiles (Full Disk), kTCCServiceSystemPolicyDesktopFolder, DownloadsFolder, DocumentsFolder, Photos, Camera, Microphone, Accessibility, PostEvent (input monitoring), Location, Contacts, Calendars, Reminders, etc.

**Known / Historical Vectors to Re-verify or Find Variants Of** (research shows these patterns repeat; always test current build):

1. **Environment / HOME / launchctl manipulation** (classic CVE-2020-9934 style)
   - Test whether tccd still honors $HOME or NFSHomeDirectory for its DB location.
   - `launchctl setenv HOME /tmp/fakehome; launchctl kickstart -k system/com.apple.tccd`

2. **Symlink / TOCTOU / mid-operation path swaps**
   - Especially in fileproviderd, copy/move operations, iCloud, Spotlight importers.
   - Example pattern (from public research): start a copy into protected folder, swap a directory component with symlink after initial checks pass.

3. **Inherited permissions via bundled interpreters / runtimes**
   - Electron apps with `RunAsNode`, `EnableNodeCliInspectArguments`, or `NODE_OPTIONS` fuses enabled.
     Test: `ELECTRON_RUN_AS_NODE=1 /path/to/EntitledApp.app/Contents/MacOS/App -e 'console.log(require("fs").readdirSync("/Users/you/Documents"))'`
   - Bundled Python (GIMP, Poedit, Inkscape, LibreOffice, etc.), Node, etc.
     Locate the interpreter inside the .app bundle and invoke with `-c` / `-e`.

4. **Dylib / plugin injection into entitled processes**
   - Check `codesign` output for `com.apple.security.cs.disable-library-validation` or missing hardened runtime.
   - Look for apps that load 3rd-party plugins, updaters (Sparkle), or have get-task-allow.
   - Test `DYLD_INSERT_LIBRARIES` or `DYLD_LIBRARY_PATH` (usually blocked, but verify).

5. **Launch Services UTI / role handler abuse**
   - Using `LSSetDefaultRoleHandlerForContentType` (or public equivalents) to become the handler for sensitive file types (e.g. .sqlite, .photoslibrary, .icloud), then `open` the file so TCC sees the request as user-intent via Launch Services.

6. **Spotlight mdimporter abuse**
   - Drop or register a custom .mdimporter that reads protected locations during indexing.
   - Force `mdimport` or `mdworker_shared`.

7. **Accessibility / VoiceOver / scrod / assistive tech**
   - com.apple.scrod and related often have or can obtain broad access. Test AppleScript / OSA / event posting.

8. **Mounting & diskarbitrationd path tricks**
   - Crafted paths with `../` that reach `~/Library/Application Support/com.apple.TCC` via mount requests.

9. **XPC client validation failures**
   - Connect to high-privilege XPC services from unsandboxed or low-priv code and request operations that touch TCC-protected resources.

10. **Legacy / SSH / automation backdoors**
    - Historical full-disk via SSH; verify current behavior.
    - `osascript`, `automator`, Shortcuts, JXA in contexts where they inherit or spoof identity.

**Validation gold standard (2025+)**: Use Apple's **TCC Target Flag**
```bash
tccutil flag check          # shows integrity_flag in user + system DBs
tccutil flag reset          # clean state (use in test env)
```
A successful bypass that can write the per-user or system TCC database and flip the flag qualifies for accelerated bounty review ($5,000 unsandboxed app, $10,000 + sandbox escape).

Monitor with the `log stream` command above while testing each vector. Record exact sequence that produces a TCC decision without a user prompt (or prompt attributed to wrong client).

## Phase 3: Local Privilege Escalation Paths

Focus on moving from standard user → root / kernel (or at least another user's context).

- SUID root binaries: inspect every one with `otool -tvV`, `strings`, `nm`. Look for:
  - Relative path exec / system()
  - Unsafe temp file creation in /tmp
  - Environment variable trust
  - TOCTOU on ownership/perms

- Writable LaunchDaemon/Agent plists or executables:
  ```bash
  ls -l /Library/LaunchDaemons/*.plist
  # check owner, and the Program/ProgramArguments target
  ```

- Insecure XPC services running as root that accept user connections and perform privileged actions (file writes, kext loads, exec, etc.).

- Historical patterns: cfprefsd, PackageKit, diskarbitration, etc. Search for similar logic in current daemons.

- Check `sudo -l` for excessive rules.

- World-writable or group-writable critical paths (rare under SIP but check /Library, /etc, user-writable /tmp races).

- Kernel: match `uname -r` against public LPEs, but note SIP + PPL + AMFI make most require additional bypasses. Look for info leaks or logic issues first.

Combine LPE + TCC bypass for maximum impact (full system data access).

## Phase 4: Deep / Advanced Techniques

- Binary & framework analysis:
  - `otool -L`, `otool -l`, `otool -tvV`
  - `codesign -dvvv --entitlements - --xml`
  - `nm -gU`, `strings | grep -i -E 'tcc|privacy|home|library|documents'`
  - If tools available: `r2`, Ghidra, or lldb on test processes (may require SIP off or entitlements).

- Dynamic tracing:
  - `fs_usage -w -f filesys`
  - `opensnoop` (if available via bpftrace or dtrace remnants)
  - `sample <pid> 5 100` or Instruments

- Filesystem search for misconfigurations:
  ```bash
  mdfind 'kMDItemFSContentChangeDate >= $time.today(-7)'
  find /Users -name TCC.db -o -name '*.entitlements' 2>/dev/null
  ```

- Review system logs for past TCC or securityd decisions that look anomalous.

- 3rd-party research cross-check: after enumeration, search public sources (with citations) for issues affecting the exact build.

## Phase 5: PoC Development & Evidence Collection (Safe)

- PoCs must be minimal and non-persistent.
- For TCC: demonstrate read of protected data (e.g. `ls ~/Documents` or `sqlite3 ~/Library/Photos/...`) or write to DB without consent prompt.
- Always capture:
  - `tccutil flag check` output pre- and post-PoC.
  - `log stream` excerpts showing the access decision.
  - Screen recording (clean system state → exploit → data access or flag set).
  - Full repro script + exact macOS build.
- Test cleanup: `tccutil flag reset` + `tccutil reset All` in test account.
- Never run destructive or data-exfiltrating PoCs on primary machine.

## Phase 6: Apple Security Bounty Reporting

1. Go to https://security.apple.com/ → Submit a Report (Apple ID login required).
2. **Include Target Flag output** for TCC issues — this is now the objective proof for fast-track review and higher rewards.
3. Report structure (copy-paste ready):
   - **Title**: Concise, e.g. "TCC Bypass: [Vector] Allows Unauthorized Access to [Photos/Documents/etc] Without Prompt on macOS [build]"
   - **Versions affected**: List exact builds tested; note whether present in latest public release.
   - **Description**: Root cause explanation. Why the design (per-process identity + user consent + DB integrity) is violated.
   - **Impact**: Data exposed (user photos metadata+content, location history, keystrokes, full disk, cross-user, etc.). Real-world attacker scenario (local unprivileged malware, malicious app the user was tricked into granting limited perms to, etc.).
   - **Reproduction Steps**: Numbered, from clean install or test user. Include all commands, clicks, and the PoC (attach minimal source or binary; explain how to build).
   - **Evidence**:
     - tccutil flag check output (before/after)
     - Relevant log excerpts
     - Video or annotated screenshots
     - Crash reports if any
   - **Suggested remediation** (optional but appreciated).
4. For kernel / full LPE: also capture the commpage Target Flag.
5. After submission: monitor the portal, answer follow-ups promptly. Awards for qualifying TCC Target Flag captures are processed faster.
6. Do **not** discuss details publicly or with other vendors until Apple has addressed it (unless coordinated).

Also file separate reports for:
- 3rd-party apps that ship with dangerous fuses or bundled interpreters (notify the vendor + Apple if the app is notarized/signed).
- Issues that don't quite meet bounty criteria (still valuable for hardening).

## Phase 7: Hardening & Defense Recommendations

**For end users / power users**:
- Stay on latest macOS + security updates.
- Review and revoke broad TCC permissions regularly (especially Full Disk Access, Accessibility, Input Monitoring).
- Only grant permissions to apps you trust; prefer App Store / well-known developers.
- Run a dedicated low-priv research/test account.
- Use FileVault.
- Consider MDM-style profiles even on personal Macs for strict TCC control (PrivacyPreferencesPolicyControl).

**For developers / software vendors**:
- Ship with hardened runtime + library validation enabled.
- Never set `get-task-allow` or disable-library-validation in release builds.
- For Electron: disable high-risk fuses (`RunAsNode`, etc.) in release.
- For apps bundling interpreters: either remove them from the bundle for macOS or drop privileges / re-exec safely.
- Use Sparkle (or updaters) securely; validate signatures strictly.

**For organizations**:
- Deploy configuration profiles that lock or pre-populate allowed TCC clients.
- Monitor TCC decisions via Endpoint Security Framework (Apple added better TCC events).
- Inventory installed apps and their entitlements periodically.
- Block unsigned / ad-hoc code execution where feasible.

**System-level improvements that would help** (for your report suggestions):
- Stronger client identity for TCC decisions (beyond bundle ID + code signing).
- Better protection of the TCC databases against TOCTOU and symlink attacks.
- Default-deny for bundled scripting runtimes inside GUI apps.
- More visible/auditable automation paths.

## Command & Tool Cheat Sheet

| Goal                        | Command |
|-----------------------------|---------|
| TCC DB query (user)        | `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT ..."` |
| Live TCC decisions         | `log stream --level debug --predicate 'subsystem == "com.apple.TCC"'` |
| Target Flag (bounty proof) | `tccutil flag check` / `tccutil flag reset` |
| Entitlements               | `codesign -d --entitlements :- /path/to/binary` |
| Mach-O load commands       | `otool -l /path` |
| Disassembly preview        | `otool -tvV /path \| head -100` |
| Signature assessment       | `spctl --assess --verbose --type execute /path` |
| Launch item inspection     | `launchctl print gui/$(id -u)/LABEL` or system/ |
| Monitor file access        | `fs_usage -w -f filesys` (or `sudo fs_usage`) |

## Public Research Sources (for cross-reference, always re-verify)

- Objective-See (Patrick Wardle) blog posts on TCC & malware
- Black Hat talks: "20+ Ways to Bypass Your macOS Privacy Mechanisms", "Knockout Win Against TCC"
- HackTricks macOS TCC section
- Research from Microsoft, SentinelOne, Jamf, AFINE, CERT Polska, individual researchers (Gergely Kalman, Wojciech Reguła, etc.)
- GitHub security advisories for recent Electron / Python interpreter TCC issues
- Apple's own bounty pages, security updates, and Target Flags documentation

When you discover something novel, this skill has done its job: you now have the process and evidence format to report it properly and contribute to a more secure macOS for everyone.

Start by running the Phase 0 + Phase 1 commands above and paste the output for analysis.
