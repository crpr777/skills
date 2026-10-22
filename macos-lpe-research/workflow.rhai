// macOS local privilege-escalation research for Apple Security Bounty.
// Authorized research on THIS Mac only. Responsible disclosure only.
// Produce Apple-ready reports for independently re-inspected paths to root.
// Do NOT weaponize: no exploit kits, no malware, no persistence, no live attacks
// on anything you do not own.

let meta = #{
    name: "macos-lpe-research",
    description: "Authorized macOS local privilege-escalation research: enumerate live LPE surfaces, adversarially verify only chains to root, draft Apple Security Bounty reports",
    when_to_use: "When hunting validatable local privilege escalation to root on a Mac you own, for responsible disclosure to Apple (security.apple.com) and macOS hardening",
    phases: [
        #{ title: "Safety", detail: "Authorize, freeze attacker model, capture SIP/build baseline" },
        #{ title: "Inventory", detail: "Enumerate SUID, launchd, XPC, sudo, writable paths, helpers" },
        #{ title: "Hunt", detail: "Deep inspection of each LPE class for concrete root chains" },
        #{ title: "Verify", detail: "Two independent fail-closed skeptics per candidate" },
        #{ title: "Report", detail: "Apple-ready reports only for dual-verified root paths" },
    ],
};

fn trimmed(s) {
    if type_of(s) == "string" {
        s.trim();
        s
    } else {
        ""
    }
}

fn nonempty(s) {
    trimmed(s) != ""
}

fn as_bool(x, fallback) {
    if x == true || x == "true" || x == 1 {
        true
    } else if x == false || x == "false" || x == 0 {
        false
    } else {
        fallback
    }
}

fn cand_key(c) {
    let a = "";
    let b = "";
    if c != () {
        if c.target_path != () { a = trimmed(c.target_path); }
        if c.title != () { b = trimmed(c.title); }
    }
    a + "|" + b
}

let SAFETY = "AUTHORIZED local macOS security research on THIS machine only, for responsible disclosure to Apple Security Bounty (https://security.apple.com/submit/) to harden macOS. ";
let RULES = "RULES: (1) Inspect only this Mac. Do not scan other hosts. "
    + "(2) Do NOT write exploits, exploit PoCs, shellcode, malware, persistence, or attack payloads. Do NOT actually escalate, replace LaunchDaemons, inject dylibs, overwrite system files, disable SIP, or run sudo that changes state. "
    + "(3) Validation = re-run inspection commands (ls, codesign, otool, plutil, launchctl print, strings, file) and quote the output. "
    + "(4) In-scope end state is ROOT (uid 0) or kernel from a STANDARD non-admin local user WITH SIP enabled. "
    + "(5) OUT OF SCOPE: TCC/privacy-only, Gatekeeper-only, expected admin->root via sudo password, issues that SIP already blocks, theoretical CWE lists, already-patched public CVEs unless you re-confirmed they still work on THIS build. "
    + "(6) Third-party apps are not Apple OS bugs; mark apple_owned=false. "
    + "(7) Empty results are valid ONLY after you actually ran the enumeration commands. Do not answer from memory. "
    + "(8) Apple rejects infeasible/theoretical/unvalidated AI reports — never claim a root path you did not independently inspect on this Mac.";

if args == () {
    pause("verification", "Pass args: { authorized: true }. Optional: max_candidates (1-8), include_third_party (bool), focus (all|suid|launchd|xpc|sudo|writable|helpers|installer|iokit). This workflow inspects THIS Mac for Apple-reportable local privilege escalation to root.");
}

let authorized = false;
if args.authorized != () {
    authorized = as_bool(args.authorized, false);
}
if args.query != () {
    let q = trimmed(args.query);
    if q == "authorized=true" || q == "true" { authorized = true; }
}
if !authorized {
    pause("verification", "This workflow performs live local LPE inspection. Re-run with args.authorized=true confirming you own this Mac and will disclose to Apple only.");
}

let max_candidates = 8;
if args.max_candidates != () && args.max_candidates >= 1 && args.max_candidates <= 8 {
    max_candidates = args.max_candidates;
}

let include_third_party = true;
if args.include_third_party != () {
    include_third_party = as_bool(args.include_third_party, true);
}

let focus = "all";
if args.focus != () {
    let fcs = trimmed(args.focus);
    if fcs != "" { focus = fcs; }
}

const VOTES = 2;

let baseline_schema = #{
    "type": "object",
    "required": ["macos_version", "build", "sip_status", "uid", "username", "notes"],
    "properties": #{
        "macos_version": #{ "type": "string" },
        "build": #{ "type": "string" },
        "sip_status": #{ "type": "string" },
        "authenticated_root": #{ "type": "string" },
        "boot_args": #{ "type": "string" },
        "uid": #{ "type": "string" },
        "username": #{ "type": "string" },
        "is_admin": #{ "type": "boolean" },
        "sudo_l": #{ "type": "string" },
        "spctl": #{ "type": "string" },
        "notes": #{ "type": "string" },
    },
};

let inventory_schema = #{
    "type": "object",
    "required": ["surface", "summary", "targets"],
    "properties": #{
        "surface": #{ "type": "string" },
        "summary": #{ "type": "string" },
        "targets": #{
            "type": "array", "maxItems": 12,
            "items": #{
                "type": "object",
                "required": ["path", "why", "privilege"],
                "properties": #{
                    "path": #{ "type": "string" },
                    "why": #{ "type": "string" },
                    "privilege": #{ "type": "string" },
                },
            },
        },
        "blockers": #{ "type": "array", "maxItems": 8, "items": #{ "type": "string" } },
        "notes": #{ "type": "string" },
    },
};

let findings_schema = #{
    "type": "object",
    "required": ["findings"],
    "properties": #{
        "findings": #{
            "type": "array", "maxItems": 4,
            "items": #{
                "type": "object",
                "required": ["id", "title", "surface", "target_path", "apple_owned", "attacker_start", "privileged_end", "chain", "evidence", "sip_blocks", "preconditions", "known_or_novel"],
                "properties": #{
                    "id": #{ "type": "string" },
                    "title": #{ "type": "string" },
                    "surface": #{ "type": "string" },
                    "target_path": #{ "type": "string" },
                    "apple_owned": #{ "type": "boolean" },
                    "attacker_start": #{ "type": "string" },
                    "privileged_end": #{ "type": "string", "enum": ["root", "kernel", "sip_bypass_then_root"] },
                    "chain": #{ "type": "string" },
                    "evidence": #{ "type": "string" },
                    "sip_blocks": #{ "type": "boolean" },
                    "preconditions": #{ "type": "string" },
                    "known_or_novel": #{ "type": "string", "enum": ["likely_novel", "variant_of_known", "known_pattern"] },
                    "fix_hint": #{ "type": "string" },
                },
            },
        },
        "notes": #{ "type": "string" },
    },
};

let verdict_schema = #{
    "type": "object",
    "required": ["real", "leads_to_root", "apple_os_bug", "sip_survives", "reason", "evidence"],
    "properties": #{
        "real": #{ "type": "boolean" },
        "leads_to_root": #{ "type": "boolean" },
        "apple_os_bug": #{ "type": "boolean" },
        "sip_survives": #{ "type": "boolean" },
        "reason": #{ "type": "string" },
        "evidence": #{ "type": "string" },
        "refutation": #{ "type": "string" },
        "fix_hint": #{ "type": "string" },
    },
};

let report_schema = #{
    "type": "object",
    "required": ["markdown", "apple_ready_count", "dropped_reason"],
    "properties": #{
        "markdown": #{ "type": "string" },
        "apple_ready_count": #{ "type": "integer" },
        "dropped_reason": #{ "type": "string" },
    },
};

let frozen = #{
    authorized: true,
    focus: focus,
    attacker_model: "standard_non_admin_local_user",
    required_end: "root_or_kernel",
    sip_must_be_on: true,
    disclosure: "https://security.apple.com/submit/",
    no_weaponize: true,
};

// ============================================================================
// Phase: Safety — live baseline
// ============================================================================
phase("Safety");
log("macos-lpe-research | focus=" + focus + " max_candidates=" + max_candidates.to_string());

let bp = SAFETY + RULES + "\n\n";
bp += "BASELINE. Run these commands with run_terminal_command and quote outputs. Do not skip.\n";
bp += "sw_vers\n";
bp += "sw_vers -productVersion; sw_vers -buildVersion\n";
bp += "uname -a\n";
bp += "csrutil status\n";
bp += "csrutil authenticated-root status\n";
bp += "sysctl kern.bootargs\n";
bp += "id; id -u; whoami; groups\n";
bp += "spctl --status\n";
bp += "sudo -n -l 2>&1 || true\n";
bp += "dsmemberutil checkmembership -U \"$(whoami)\" -G admin 2>&1 || true\n";
bp += "Return macos_version, build, sip_status, uid, username, is_admin, notes. If a command fails, record the error in notes — do not invent values.\n";
bp += "<frozen-json>\n" + json_encode(frozen) + "\n</frozen-json>";

let base = agent(bp, #{
    label: "baseline",
    capability_mode: "execute",
    output_schema: baseline_schema,
    phase: "Safety",
});

let macos_version = "unknown";
let build = "unknown";
let sip_status = "unknown";
let uid = "unknown";
let username = "unknown";
let is_admin = false;
let baseline_notes = "baseline agent produced no usable schema output";

if base != () && base.success && base.output != () {
    if base.output.macos_version != () { macos_version = trimmed(base.output.macos_version); }
    if base.output.build != () { build = trimmed(base.output.build); }
    if base.output.sip_status != () { sip_status = trimmed(base.output.sip_status); }
    if base.output.uid != () { uid = trimmed(base.output.uid); }
    if base.output.username != () { username = trimmed(base.output.username); }
    if base.output.is_admin != () { is_admin = as_bool(base.output.is_admin, false); }
    if base.output.notes != () { baseline_notes = trimmed(base.output.notes); }
    log("baseline macOS=" + macos_version + " build=" + build + " sip=" + sip_status + " uid=" + uid);
} else {
    log("baseline agent failed; continuing with unknown build (findings still require live evidence)");
}

frozen.macos_version = macos_version;
frozen.build = build;
frozen.sip_status = sip_status;
frozen.uid = uid;
frozen.username = username;
frozen.is_admin = is_admin;

let frozen_json = json_encode(frozen);

// ============================================================================
// Phase: Inventory — fixed LPE surfaces
// ============================================================================
phase("Inventory");

let surfaces = [
    #{
        id: "suid",
        title: "SUID/SGID and setuid helpers",
        cmds: "find /usr/bin /usr/sbin /bin /sbin /usr/libexec /opt /usr/local /Applications /Library -xdev -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null; ls -l /usr/bin/sudo /usr/bin/login /usr/libexec/security_authtrampoline 2>/dev/null; for b in $(find /usr/bin /usr/sbin /usr/libexec -perm -4000 -type f 2>/dev/null); do echo === $b; ls -lO $b; codesign -dv --entitlements - $b 2>&1 | head -40; done",
        hunt: "SUID root binaries that exec relative paths, trust env, write unsafe temps, or drop to attacker-controlled config. Ignore standard expected SUID (sudo, passwd, crontab) unless you find a NEW logic bug.",
    },
    #{
        id: "launchd",
        title: "LaunchDaemons/Agents and privileged jobs",
        cmds: "ls -laO /Library/LaunchDaemons /Library/LaunchAgents /System/Library/LaunchDaemons 2>/dev/null | head -200; ls -la ~/Library/LaunchAgents 2>/dev/null; echo '--- plist perms ---'; find /Library/LaunchDaemons /Library/LaunchAgents -name '*.plist' -maxdepth 1 -exec ls -lO {} \\; 2>/dev/null; echo '--- Program paths ---'; for p in /Library/LaunchDaemons/*.plist; do echo FILE $p; ls -lO $p; plutil -extract Label raw $p 2>/dev/null; plutil -extract UserName raw $p 2>/dev/null; plutil -extract Program raw $p 2>/dev/null; plutil -extract ProgramArguments raw $p 2>/dev/null; done",
        hunt: "User-writable plists or Program binaries that launchd will execute as root. Disabled Apple daemons are not findings. Check owner, mode, and the executable each Program/ProgramArguments points at.",
    },
    #{
        id: "xpc",
        title: "Root XPC services and privileged helpers",
        cmds: "ls /Library/PrivilegedHelperTools 2>/dev/null; ls -lO /Library/PrivilegedHelperTools 2>/dev/null; echo '--- SMJobBless helpers ---'; find /Library/PrivilegedHelperTools /Library/LaunchDaemons -type f 2>/dev/null | head -80; echo '--- sample MachServices ---'; for p in /Library/LaunchDaemons/*.plist /Library/PrivilegedHelperTools/*; do echo FILE $p; ls -lO $p 2>/dev/null; codesign -d --entitlements - $p 2>&1 | head -30; done",
        hunt: "XPC / Mach services running as root that accept connections from unsandboxed user code and perform privileged file writes, exec, kext load, or installer ops without authorization. Check SMJobBless helpers and PrivilegedHelperTools.",
    },
    #{
        id: "sudo",
        title: "sudoers, authorization rights, auth plugins",
        cmds: "ls -lO /etc/sudoers /etc/sudoers.d /etc/pam.d /Library/Security/SecurityAgentPlugins /System/Library/Security/AuthorizationPlugins 2>/dev/null; cat /etc/sudoers 2>/dev/null | head -5 || echo 'cannot read sudoers (expected)'; ls /etc/sudoers.d 2>/dev/null; sudo -n -l 2>&1 || true; ls -lO /etc/authorization 2>/dev/null; security authorizationdb read system.privilege.admin 2>/dev/null | head -40",
        hunt: "NOPASSWD sudo rules, world-writable sudoers.d, rogue authorization plugins, over-broad rights that let a standard user obtain root without an admin password. Expected admin-group sudo is NOT a finding.",
    },
    #{
        id: "writable",
        title: "Writable privileged paths and TOCTOU",
        cmds: "ls -ldO / /usr /usr/local /Library /Library/LaunchDaemons /etc /etc/periodic /private/etc /private/tmp /tmp /var /var/root /usr/local/bin /opt 2>/dev/null; find /Library /usr/local /opt /etc /private/etc -xdev -perm -0002 -type d 2>/dev/null | head -80; find /Library /usr/local /opt -xdev -perm -0002 -type f 2>/dev/null | head -80; ls -lO /etc/periodic /usr/lib/cron 2>/dev/null",
        hunt: "World/group-writable directories or files that a root process later executes or loads (cron, periodic, PATH, LaunchDaemon Program, sudoers, pam). SIP-protected paths that a standard user cannot write are NOT findings.",
    },
    #{
        id: "helpers",
        title: "Over-entitled privileged binaries and injection",
        cmds: "echo '--- PrivilegedHelperTools entitlements ---'; for b in /Library/PrivilegedHelperTools/* /usr/libexec/*d; do [ -f \"$b\" ] || continue; echo === $b; ls -lO $b; codesign -dv --entitlements - \"$b\" 2>&1 | grep -E 'get-task-allow|disable-library-validation|allow-unsigned|com.apple.private|rootless|task_for_pid' || true; done | head -200; echo '--- DYLD ---'; sysctl kern.dyld 2>/dev/null || true",
        hunt: "Privileged Apple or helper binaries with get-task-allow, disable-library-validation, or missing hardened runtime that a standard user can inject into to run as root. DYLD_INSERT_LIBRARIES is usually blocked — only report if you proved it still works on THIS build with evidence.",
    },
    #{
        id: "installer",
        title: "PackageKit, installd, softwareupdate, system_installd",
        cmds: "ls -lO /System/Library/PrivateFrameworks/PackageKit.framework/Support /usr/libexec/installd /usr/libexec/system_installd /usr/libexec/softwareupdated 2>/dev/null; codesign -dv --entitlements - /usr/libexec/installd 2>&1 | head -50; launchctl print system/com.apple.installd 2>&1 | head -40; launchctl print system/com.apple.softwareupdated 2>&1 | head -40; ls /Library/Apple/System/Library/Receipts 2>/dev/null | head",
        hunt: "Unprivileged clients talking to installd/PackageKit/softwareupdated that can write root-owned files, run scripts as root, or skip signature/SIP checks. Historical patterns: pkg postinstall as root, fake receipts, path traversal in Installer.",
    },
    #{
        id: "iokit",
        title: "IOKit user clients, kexts, kernel-adjacent",
        cmds: "csrutil status; kmutil showloaded 2>/dev/null | grep -v com.apple | head -40; kextstat 2>/dev/null | grep -v com.apple | head -40; ls /Library/Extensions /System/Library/Extensions 2>/dev/null | head; system_profiler SPHardwareDataType 2>/dev/null | head -20",
        hunt: "Non-Apple kexts or IOKit user clients reachable from userland that could yield kernel RW/exec. On SIP+PPL default Macs, unsigned kext load is blocked — only report a kernel path if the user client is loaded NOW and the interface is reachable without SIP off. Do not speculate.",
    },
];

let inv_jobs = [];
for s in surfaces {
    if focus != "all" && focus != s.id {
        continue;
    }
    let ip = SAFETY + RULES + "\n\n";
    ip += "INVENTORY one LPE surface on THIS Mac. You MUST run the commands. Do not invent paths.\n";
    ip += "Surface id: " + s.id + "\n";
    ip += "Title: " + s.title + "\n";
    ip += "Commands to run (adapt if a path is missing; capture stderr):\n" + s.cmds + "\n\n";
    ip += "What to look for: " + s.hunt + "\n";
    ip += "macOS " + macos_version + " build " + build + " SIP=" + sip_status + " uid=" + uid + "\n";
    ip += "Return surface=" + s.id + ", summary, and targets[{path, why, privilege}]. privilege should be root/kernel/unknown. "
        + "Include a target only if a STANDARD user might reach it. blockers = SIP/signing/auth that likely prevent LPE.\n";
    ip += "Empty targets is valid after a real scan.\n";
    ip += "<frozen-json>\n" + frozen_json + "\n</frozen-json>";
    inv_jobs.push(#{
        prompt: ip,
        label: "inv-" + s.id,
        capability_mode: "execute",
        output_schema: inventory_schema,
        phase: "Inventory",
    });
}

if inv_jobs.len() == 0 {
    pause("verification", "args.focus matched no surface. Use all|suid|launchd|xpc|sudo|writable|helpers|installer|iokit.");
}

let inv_results = parallel(inv_jobs);
let inventories = [];
let inv_i = 0;
for r in inv_results {
    if r != () && r.success && r.output != () && r.output.surface != () {
        inventories.push(r.output);
    } else {
        log("inventory slot failed index=" + inv_i.to_string());
    }
    inv_i += 1;
}
log("inventory maps=" + inventories.len().to_string() + "/" + inv_jobs.len().to_string());
let inventories_json = json_encode(inventories);

// ============================================================================
// Phase: Hunt — specialists produce candidate root chains
// ============================================================================
phase("Hunt");

let hunt_jobs = [];
for s in surfaces {
    if focus != "all" && focus != s.id {
        continue;
    }
    let hp = SAFETY + RULES + "\n\n";
    hp += "HUNT concrete local privilege-escalation CANDIDATES that lead to ROOT on THIS Mac.\n";
    hp += "Surface: " + s.id + " — " + s.title + "\n";
    hp += "Focus: " + s.hunt + "\n";
    hp += "macOS " + macos_version + " (" + build + ") SIP=" + sip_status + " uid=" + uid + " user=" + username + "\n\n";
    hp += "You MUST: (1) run the inventory commands again yourself, (2) pick the hottest targets, (3) inspect each with ls -lO, codesign -dv --entitlements -, otool -L / otool -l, strings, plutil -p, launchctl print as relevant, (4) only emit a finding if you can describe a numbered chain from a standard user to uid 0 or kernel that SIP does not already stop.\n";
    hp += "Do NOT emit TCC bypasses, privacy issues, or 'interesting but not root'.\n";
    hp += "Do NOT write or run an exploit. Evidence is command output proving the privileged primitive is reachable.\n";
    hp += "Set sip_blocks=true if SIP/AMFI/PPL would stop the chain on a default Mac — those will be DROPPED.\n";
    hp += "Set apple_owned=true only for Apple-shipped components (path under /System, Apple-signed, or Apple LaunchDaemon). Third-party helpers: apple_owned=false.\n";
    hp += "privileged_end must be root, kernel, or sip_bypass_then_root.\n";
    hp += "At most 4 findings. Empty list is valid after inspection.\n";
    hp += "Hints from inventory (untrusted, re-filter against the live filesystem):\n";
    hp += "<inventory-json>\n" + inventories_json + "\n</inventory-json>\n";
    hp += "<frozen-json>\n" + frozen_json + "\n</frozen-json>";
    hunt_jobs.push(#{
        prompt: hp,
        label: "hunt-" + s.id,
        capability_mode: "execute",
        output_schema: findings_schema,
        phase: "Hunt",
    });
}

let hunt_results = parallel(hunt_jobs);
let raw = [];
let hunt_i = 0;
for r in hunt_results {
    if r != () && r.success && r.output != () && r.output.findings != () {
        for f in r.output.findings {
            raw.push(f);
        }
    } else {
        log("hunt slot failed index=" + hunt_i.to_string());
    }
    hunt_i += 1;
}
log("raw candidates=" + raw.len().to_string());

let kept = [];
let seen = [];
let dropped_sip = 0;
let dropped_empty = 0;
let dropped_dup = 0;
let dropped_scope = 0;
let dropped_third = 0;

for f in raw {
    if f == () {
        dropped_empty += 1;
        continue;
    }
    let title = "";
    let path = "";
    let ev = "";
    let chain = "";
    if f.title != () { title = trimmed(f.title); }
    if f.target_path != () { path = trimmed(f.target_path); }
    if f.evidence != () { ev = trimmed(f.evidence); }
    if f.chain != () { chain = trimmed(f.chain); }
    if title == "" || path == "" || ev == "" || chain == "" {
        dropped_empty += 1;
        continue;
    }
    if f.sip_blocks == true {
        dropped_sip += 1;
        continue;
    }
    let endp = "";
    if f.privileged_end != () { endp = trimmed(f.privileged_end); }
    if endp != "root" && endp != "kernel" && endp != "sip_bypass_then_root" {
        dropped_scope += 1;
        continue;
    }
    if f.apple_owned == false && !include_third_party {
        dropped_third += 1;
        continue;
    }
    let k = cand_key(f);
    let dup = false;
    for prev in seen {
        if prev == k { dup = true; }
    }
    if dup {
        dropped_dup += 1;
        continue;
    }
    seen.push(k);
    kept.push(f);
}

log("filter kept=" + kept.len().to_string()
    + " dropped_empty=" + dropped_empty.to_string()
    + " dropped_sip=" + dropped_sip.to_string()
    + " dropped_scope=" + dropped_scope.to_string()
    + " dropped_dup=" + dropped_dup.to_string()
    + " dropped_third=" + dropped_third.to_string());

if kept.len() > max_candidates {
    log("capping candidates " + kept.len().to_string() + " -> " + max_candidates.to_string());
    let capped = [];
    let ci = 0;
    for f in kept {
        if ci < max_candidates {
            capped.push(f);
        }
        ci += 1;
    }
    kept = capped;
}

// ============================================================================
// Phase: Verify — two fail-closed skeptics per candidate
// ============================================================================
phase("Verify");

let confirmed = [];
if kept.len() == 0 {
    log("no candidates survived hunt filter; skipping verify");
} else {
    let vjobs = [];
    let fi = 0;
    for f in kept {
        let vote = 0;
        while vote < VOTES {
            let vp = SAFETY + RULES + "\n\n";
            vp += "ADVERSARIAL VERIFICATION. Your job is to REFUTE this LPE claim unless live evidence on THIS Mac proves a standard user can reach root/kernel with SIP on.\n";
            vp += "Default real=false, leads_to_root=false. Set them true ONLY if you independently re-inspected the target (re-run ls/codesign/otool/plutil/launchctl) and the chain still holds.\n";
            vp += "Fail closed: missing files, SIP blocks, needs admin already, TCC-only, third-party mis-tagged as Apple, or evidence you did not re-collect => real=false.\n";
            vp += "Do NOT run an exploit. Quote the command output that confirms or kills the claim.\n";
            vp += "macOS " + macos_version + " build " + build + " SIP=" + sip_status + "\n";
            vp += "Vote index " + vote.to_string() + " of candidate " + fi.to_string() + ".\n";
            vp += "<candidate-json>\n" + json_encode(f) + "\n</candidate-json>\n";
            vp += "<frozen-json>\n" + frozen_json + "\n</frozen-json>";
            vjobs.push(#{
                prompt: vp,
                label: "verify-" + fi.to_string() + "-v" + vote.to_string(),
                capability_mode: "execute",
                output_schema: verdict_schema,
                phase: "Verify",
            });
            vote += 1;
        }
        fi += 1;
    }

    let verdicts = parallel(vjobs);
    let counts = [];
    let apple_votes = [];
    let evid_join = [];
    for f in kept {
        counts.push(0);
        apple_votes.push(0);
        evid_join.push("");
    }

    let vi = 0;
    for v in verdicts {
        let fidx = vi / VOTES;
        if v != () && v.success && v.output != () {
            let ok = v.output.real == true
                && v.output.leads_to_root == true
                && v.output.sip_survives == true
                && v.output.evidence != ()
                && trimmed(v.output.evidence) != "";
            if ok {
                counts[fidx] = counts[fidx] + 1;
                if v.output.apple_os_bug == true {
                    apple_votes[fidx] = apple_votes[fidx] + 1;
                }
                let evs = evid_join[fidx];
                evid_join[fidx] = evs + "\n\n--- verifier " + (vi % VOTES).to_string() + " ---\n" + trimmed(v.output.evidence);
            }
        }
        vi += 1;
    }

    let ki = 0;
    for f in kept {
        if counts[ki] >= VOTES {
            let row = f;
            row.verifier_evidence = evid_join[ki];
            row.apple_os_bug_votes = apple_votes[ki];
            confirmed.push(row);
        } else {
            log("rejected candidate index=" + ki.to_string() + " votes=" + counts[ki].to_string() + "/" + VOTES.to_string());
        }
        ki += 1;
    }
    log(confirmed.len().to_string() + "/" + kept.len().to_string() + " candidates survived dual verification");
}

// ============================================================================
// Phase: Report
// ============================================================================
phase("Report");

let apple_confirmed = [];
let vendor_confirmed = [];
for f in confirmed {
    let is_apple = f.apple_owned == true;
    if f.apple_os_bug_votes != () && f.apple_os_bug_votes >= VOTES {
        is_apple = true;
    }
    if f.apple_owned == false {
        is_apple = false;
    }
    if is_apple {
        apple_confirmed.push(f);
    } else {
        vendor_confirmed.push(f);
    }
}

let fallback = "";
fallback += "# macOS local privilege-escalation research\n\n";
fallback += "Authorized inspection of this Mac for Apple Security Bounty. ";
fallback += "Fail-closed: only dual-verified chains from a standard user to root/kernel with SIP on are listed.\n\n";
fallback += "- macOS: " + macos_version + " (" + build + ")\n";
fallback += "- SIP: " + sip_status + "\n";
fallback += "- uid: " + uid + " user: " + username + "\n";
fallback += "- Dual-verified root paths: " + confirmed.len().to_string() + "\n";
fallback += "- Apple-owned: " + apple_confirmed.len().to_string() + "\n";
fallback += "- Third-party: " + vendor_confirmed.len().to_string() + "\n";
fallback += "- Hunt filter drops: empty=" + dropped_empty.to_string() + " sip=" + dropped_sip.to_string() + " scope=" + dropped_scope.to_string() + " dup=" + dropped_dup.to_string() + "\n";
fallback += "- Baseline notes: " + baseline_notes + "\n\n";
fallback += "Disclosure: https://security.apple.com/submit/ — do not publish before Apple ships a fix.\n";
fallback += "This workflow does not generate exploits. Apple's maximum LPE awards require a researcher-built PoC using the Commpage Target Flag (https://security.apple.com/bounty/target-flags/).\n\n";

if apple_confirmed.len() == 0 && vendor_confirmed.len() == 0 {
    fallback += "## Result\n\nNo independently validatable local privilege-escalation path to root was confirmed on this Mac.\n\n";
    fallback += "That is a successful hardening outcome. Remaining work: keep SIP on, stay current, re-run after OS updates and after installing privileged third-party software.\n";
} else {
    fallback += "## Dual-verified findings\n\n";
    let n = 1;
    for f in apple_confirmed {
        fallback += "### A" + n.to_string() + " (Apple) — " + trimmed(f.title) + "\n\n";
        fallback += "- Target: `" + trimmed(f.target_path) + "`\n";
        fallback += "- Surface: " + trimmed(f.surface) + "\n";
        fallback += "- End: " + trimmed(f.privileged_end) + "\n";
        fallback += "- Novelty: " + trimmed(f.known_or_novel) + "\n\n";
        fallback += "**Chain**\n\n" + trimmed(f.chain) + "\n\n";
        fallback += "**Evidence**\n\n" + trimmed(f.evidence) + "\n\n";
        if f.verifier_evidence != () {
            fallback += "**Verifier re-inspection**\n\n" + trimmed(f.verifier_evidence) + "\n\n";
        }
        fallback += "Submit at https://security.apple.com/submit/ with numbered repro steps. Do not attach a weaponized exploit from this workflow.\n\n";
        n += 1;
    }
    let m = 1;
    for f in vendor_confirmed {
        fallback += "### V" + m.to_string() + " (third-party — not an Apple OS bug) — " + trimmed(f.title) + "\n\n";
        fallback += "- Target: `" + trimmed(f.target_path) + "`\n";
        fallback += "- Report to the vendor, not as an Apple OS LPE.\n\n";
        fallback += trimmed(f.chain) + "\n\n";
        m += 1;
    }
}

fallback += "\n## Hardening\n\n";
fallback += "- Keep SIP enabled; do not boot with disabling boot-args.\n";
fallback += "- Stay on the latest macOS security update (https://support.apple.com/en-us/HT201222).\n";
fallback += "- Audit `/Library/LaunchDaemons`, `/Library/PrivilegedHelperTools`, and sudoers after installing software.\n";
fallback += "- Uninstall unused privileged helpers. Prefer App Store / notarized software.\n";
fallback += "- Use FileVault and a non-admin day-to-day account.\n";

let rp = SAFETY + RULES + "\n\n";
rp += "Write the FINAL markdown report for the operator. Dual-verified findings only. If the list is empty, say so clearly — do not invent issues.\n";
rp += "For each Apple-owned finding, produce a paste-ready Apple Security Bounty section: Title, Versions affected (this build), Description, Impact (standard user -> root), numbered Reproduction Steps (inspection commands, not an exploit), Evidence, Suggested remediation, Target Flag note (Commpage required for max LPE reward; this workflow did not run a PoC).\n";
rp += "Remind: do not publicly disclose until Apple ships a fix. Submit at https://security.apple.com/submit/.\n";
rp += "macOS " + macos_version + " build " + build + " SIP=" + sip_status + "\n";
rp += "<apple-findings-json>\n" + json_encode(apple_confirmed) + "\n</apple-findings-json>\n";
rp += "<vendor-findings-json>\n" + json_encode(vendor_confirmed) + "\n</vendor-findings-json>\n";
rp += "<frozen-json>\n" + frozen_json + "\n</frozen-json>";

let rpt = agent(rp, #{
    label: "report",
    capability_mode: "read-only",
    output_schema: report_schema,
    phase: "Report",
});

let report_md = fallback;
if rpt != () && rpt.success && rpt.output != () && rpt.output.markdown != () {
    let md = trimmed(rpt.output.markdown);
    if md != "" { report_md = md; }
}

let artifact = write_scratch_file("lpe-report.md", report_md);
log("report written " + artifact + " apple=" + apple_confirmed.len().to_string() + " vendor=" + vendor_confirmed.len().to_string());

complete(#{
    path: artifact,
    summary: apple_confirmed.len().to_string() + " Apple-owned dual-verified root path(s); "
        + vendor_confirmed.len().to_string() + " third-party; hunt kept "
        + kept.len().to_string() + " before verify",
    macos_version: macos_version,
    build: build,
    sip_status: sip_status,
    apple_ready_count: apple_confirmed.len(),
    vendor_count: vendor_confirmed.len(),
    report: report_md,
});
