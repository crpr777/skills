// Mythos Vuln Research — OpenMythos-mapped multi-agent pipeline
// Architecture: Prelude → Recurrent MoE experts (looped) → Verify → Coda
// Inspired by https://github.com/kyegomez/OpenMythos and local mythos_re harness.
//
// Safety posture (hard constraints for every agent):
// - Authorized security research + responsible disclosure only.
// - Produce findings, impact, fix guidance, and minimal verification repros
//   suitable for vendor/bounty reports — NOT weaponized exploit kits,
//   malware, mass scanners against third parties, or live attacks on systems
//   outside the declared authorized scope.
// - Prefer defensive remediation over offensive packaging.

let meta = #{
    name: "mythos-vuln-research",
    description: "Scale vulnerability research with OpenMythos-style prelude/recurrent/coda loops; find high-signal issues and produce responsible-disclosure packages with minimal verification repros",
    when_to_use: "When auditing authorized codebases, browser extensions, or local targets for novel vulns at scale (0-day hunting under responsible disclosure)",
    phases: [
        #{ title: "Scope", detail: "Authorize, normalize targets, freeze input injection e" },
        #{ title: "Prelude", detail: "Surface inventory + attack-surface map per target" },
        #{ title: "Rank", detail: "Select deep-dive targets by risk signal" },
        #{ title: "Recurrent", detail: "MoE expert loops with frozen-e reinjection and depth phasing" },
        #{ title: "Verify", detail: "Adversarial fail-closed verification of candidate findings" },
        #{ title: "Coda", detail: "Disclosure packages, minimal repros, fix guidance, final report" },
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

fn has_substr(s, sub) {
    if type_of(s) != "string" || type_of(sub) != "string" {
        false
    } else if sub.len() == 0 {
        true
    } else if s.len() < sub.len() {
        false
    } else {
        let found = false;
        let i = 0;
        let max_i = s.len() - sub.len();
        while i <= max_i {
            if s.sub_string(i, sub.len()) == sub {
                found = true;
                i = max_i + 1;
            } else {
                i += 1;
            }
        }
        found
    }
}

// Extract https://... tokens (github / bugcrowd / generic) from free text.
fn extract_urls(text) {
    let out = [];
    if type_of(text) != "string" {
        return out;
    }
    let i = 0;
    let n = text.len();
    while i < n {
        let rest_len = n - i;
        let is_http = false;
        if rest_len >= 8 && text.sub_string(i, 8) == "https://" {
            is_http = true;
        } else if rest_len >= 7 && text.sub_string(i, 7) == "http://" {
            is_http = true;
        }
        if is_http {
            let j = i;
            while j < n {
                let ch = text.sub_string(j, 1);
                if ch == " " || ch == "\n" || ch == "\t" || ch == "," || ch == ")" || ch == "]" || ch == "\"" || ch == "'" {
                    break;
                }
                j += 1;
            }
            let url = text.sub_string(i, j - i);
            // strip trailing punctuation
            while url.len() > 0 {
                let last = url.sub_string(url.len() - 1, 1);
                if last == "." || last == ";" || last == ":" {
                    url = url.sub_string(0, url.len() - 1);
                } else {
                    break;
                }
            }
            if url.len() > 8 {
                out.push(url);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn phase_name(loop_t) {
    // Loop-index embedding analog: early = surface, mid = semantic/hypothesis, late = exploit-class
    if loop_t <= 0 {
        "surface"
    } else if loop_t == 1 {
        "semantic"
    } else if loop_t == 2 {
        "hypothesis"
    } else {
        "exploit_class"
    }
}

// --- args guards ---
if args == () {
    pause("verification", "Pass args: { authorized: true, targets: [\"/path/or/repo\"], scope: \"what you own/may test\" }. Optional: max_targets, max_loops, profile, deep_k, domain. Slash form: /mythos-vuln-research <github-url> bounty <bugcrowd-url> also works.");
}

// Free-text query from slash commands (host often maps the rest of the line to query/objective)
let free_text = "";
if args.query != () { free_text = trimmed(args.query); }
if free_text == "" && args.objective != () { free_text = trimmed(args.objective); }

let urls_from_text = extract_urls(free_text);
let bounty_urls = [];
let github_urls = [];
for u in urls_from_text {
    if has_substr(u, "bugcrowd.com/engagements") || has_substr(u, "hackerone.com/") || has_substr(u, "yeswehack.com/") {
        bounty_urls.push(u);
    } else if has_substr(u, "github.com/") {
        github_urls.push(u);
    }
}

let authorized = false;
if args.authorized != () {
    authorized = args.authorized == true || args.authorized == "true" || args.authorized == 1;
}
// Public bug-bounty / VDP slash launches: program URL + research target ⇒ authorized under program safe harbor
if !authorized && bounty_urls.len() > 0 && (github_urls.len() > 0 || args.targets != () || args.target != () || args.path != ()) {
    authorized = true;
    log("authorized via public bounty/VDP program URL in free-text launch (safe-harbor research only)");
}
if !authorized && free_text != "" && has_substr(free_text, "authorized=true") {
    authorized = true;
}
if !authorized {
    pause("verification", "Safety gate: set args.authorized=true for systems you own/may test, OR launch with a public bounty/VDP URL (e.g. bugcrowd.com/engagements/...) plus a github.com or local target. Resume cannot change frozen args — start a new run.");
}

let scope_text = "";
if args.scope != () { scope_text = trimmed(args.scope); }
if scope_text == "" && free_text != "" {
    if bounty_urls.len() > 0 {
        scope_text = "Public bug bounty / VDP research under program brief safe harbor. Free-text objective: " + free_text;
    } else {
        scope_text = "Research objective (from slash query): " + free_text;
    }
}
if scope_text == "" {
    pause("verification", "Pass args.scope — a short statement of authorized boundaries (e.g. 'Bugcrowd Mattermost MBB; researcher cloud/self-hosted only').");
}

// Normalize targets from several shapes
let raw_targets = [];
if args.targets != () {
    if type_of(args.targets) == "array" {
        raw_targets = args.targets;
    } else if type_of(args.targets) == "string" {
        raw_targets = [args.targets];
    }
} else if args.target != () {
    raw_targets = [args.target];
} else if args.path != () {
    raw_targets = [args.path];
} else if github_urls.len() > 0 {
    raw_targets = github_urls;
} else if free_text != "" && !has_substr(free_text, "http") {
    // bare local path as the whole query
    raw_targets = [free_text];
}

if raw_targets.len() == 0 {
    pause("verification", "Pass args.targets (array of local paths or repo URLs) or include a github.com URL in the slash query.");
}

let max_targets = 6;
if args.max_targets != () && args.max_targets >= 1 && args.max_targets <= 16 {
    max_targets = args.max_targets;
}

let max_loops = 3;
if args.max_loops != () && args.max_loops >= 1 && args.max_loops <= 4 {
    max_loops = args.max_loops;
}

let deep_k = 3;
if args.deep_k != () && args.deep_k >= 1 && args.deep_k <= 8 {
    deep_k = args.deep_k;
}

let profile = "standard";
if args.profile != () {
    let p = trimmed(args.profile);
    if p == "light" || p == "standard" || p == "deep" || p == "paranoid" {
        profile = p;
    }
} else if free_text != "" && (has_substr(free_text, "go deep") || has_substr(free_text, "paranoid") || has_substr(free_text, "0-day") || has_substr(free_text, "0 day")) {
    profile = "deep";
    log("profile=deep inferred from free-text objective");
}

let domain = "auto";
if args.domain != () {
    let d = trimmed(args.domain);
    if d == "extension" || d == "codebase" || d == "service" || d == "auto" {
        domain = d;
    }
}

// Cap & sanitize target list (script enforces scale, not agents)
let targets = [];
for t in raw_targets {
    let ts = trimmed(t);
    if ts != "" && targets.len() < max_targets {
        // de-dupe
        let seen = false;
        for existing in targets {
            if existing == ts { seen = true; }
        }
        if !seen {
            targets.push(ts);
        }
    }
}
if raw_targets.len() > max_targets {
    log("capped targets " + raw_targets.len().to_string() + " → " + max_targets.to_string());
}
if targets.len() == 0 {
    pause("verification", "No usable targets after normalization.");
}

// Expert roster (MoE-style). Sparse activation by loop phase.
let all_experts = [
    "trust_boundaries",
    "authn_authz",
    "injection_deserialization",
    "crypto_secrets",
    "supply_chain_config",
    "ipc_messaging",
];

// --- Schemas ---
let prelude_schema = #{
    "type": "object",
    "required": ["target", "kind", "surface_summary", "hotspots", "signals", "risk_hint", "confidence"],
    "properties": #{
        "target": #{ "type": "string" },
        "kind": #{ "type": "string", "enum": ["extension", "codebase", "service", "unknown"] },
        "surface_summary": #{ "type": "string" },
        "hotspots": #{
            "type": "array", "maxItems": 12,
            "items": #{
                "type": "object",
                "required": ["path", "why"],
                "properties": #{
                    "path": #{ "type": "string" },
                    "why": #{ "type": "string" },
                },
            },
        },
        "signals": #{
            "type": "array", "maxItems": 16, "items": #{ "type": "string" },
        },
        "risk_hint": #{ "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
        "confidence": #{ "type": "number" },
        "mythos_re_notes": #{ "type": "string" },
    },
};

let findings_schema = #{
    "type": "object",
    "required": ["findings"],
    "properties": #{
        "findings": #{
            "type": "array", "maxItems": 6,
            "items": #{
                "type": "object",
                "required": ["id", "title", "severity", "category", "root_cause", "evidence", "impact", "confidence", "novel_hypothesis"],
                "properties": #{
                    "id": #{ "type": "string" },
                    "title": #{ "type": "string" },
                    "severity": #{ "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
                    "category": #{ "type": "string" },
                    "root_cause": #{ "type": "string" },
                    "evidence": #{ "type": "string", "description": "file:line quotes, API names, config keys actually inspected" },
                    "impact": #{ "type": "string" },
                    "confidence": #{ "type": "number" },
                    "novel_hypothesis": #{
                        "type": "boolean",
                        "description": "true if this may be novel / unpatched (0-day class); false if known-pattern restatement",
                    },
                    "paths": #{ "type": "array", "maxItems": 8, "items": #{ "type": "string" } },
                    "preconditions": #{ "type": "string" },
                },
            },
        },
        "halt_component": #{
            "type": "boolean",
            "description": "ACT-style: true if this expert is confident enough to stop deepening this area",
        },
        "notes": #{ "type": "string" },
    },
};

let verdict_schema = #{
    "type": "object",
    "required": ["real", "severity", "reason", "evidence", "novelty"],
    "properties": #{
        "real": #{ "type": "boolean" },
        "severity": #{ "type": "string", "enum": ["critical", "high", "medium", "low", "info", "invalid"] },
        "reason": #{ "type": "string" },
        "evidence": #{ "type": "string" },
        "novelty": #{ "type": "string", "enum": ["likely_novel", "known_pattern", "uncertain"] },
        "fix_hint": #{ "type": "string" },
    },
};

let repro_schema = #{
    "type": "object",
    "required": ["finding_id", "disclosure_title", "steps", "expected_result", "fix_recommendation", "repro_kind"],
    "properties": #{
        "finding_id": #{ "type": "string" },
        "disclosure_title": #{ "type": "string" },
        "steps": #{ "type": "array", "maxItems": 12, "items": #{ "type": "string" } },
        "expected_result": #{ "type": "string" },
        "fix_recommendation": #{ "type": "string" },
        "repro_kind": #{
            "type": "string",
            "enum": ["static_proof", "local_lab_repro", "config_demo", "unit_test_sketch"],
            "description": "Minimal verification only — no weaponized payload packaging",
        },
        "minimal_artifact": #{
            "type": "string",
            "description": "Short code/config snippet for the vendor report if needed; never a full attack kit",
        },
        "out_of_scope_notes": #{ "type": "string" },
    },
};

// Shared safety preamble injected into every agent prompt
let SAFETY = "You are performing AUTHORIZED vulnerability research only. Scope (JSON): ";
let SAFETY2 = ". Rules: (1) Only inspect local paths / declared targets. (2) Do not attack third-party live systems. "
    + "(3) Prefer root-cause analysis and defensive fixes. (4) If you describe reproduction, keep it a MINIMAL "
    + "verification repro for responsible disclosure — no weaponized exploits, no malware, no mass-scan tooling. "
    + "(5) Mark novelty honestly. (6) Use tools (read_file, grep, list_dir, run_terminal_command when allowed) — "
    + "never invent file contents. Empty findings are valid only after real inspection.";

// ============================================================================
// Phase: Scope — freeze input injection e (OpenMythos e)
// ============================================================================
phase("Scope");
log("Mythos vuln research | targets=" + targets.len().to_string()
    + " max_loops=" + max_loops.to_string()
    + " deep_k=" + deep_k.to_string()
    + " profile=" + profile
    + " domain=" + domain);

let e = #{
    targets: targets,
    scope: scope_text,
    profile: profile,
    domain: domain,
    max_loops: max_loops,
    architecture: "openmythos_rdt",
    disclosure: "responsible",
};

// ============================================================================
// Phase: Prelude — surface inventory per target (parallel fan-out)
// ============================================================================
phase("Prelude");
let prelude_jobs = [];
let ti = 0;
for tpath in targets {
    let pp = SAFETY + json_encode(scope_text) + SAFETY2 + "\n\n";
    pp += "PRELUDE (OpenMythos-style): Build the frozen attack-surface map for one target. ";
    pp += "Inspect the filesystem/repo with tools. If it looks like a browser extension (manifest.json v2/v3), kind=extension. ";
    pp += "If domain hint is extension and mythos_re is available on the machine, you MAY run ";
    pp += "`python3 -m mythos_re analyze <path> --loops 4 --profile light` with execute tools and summarize its findings into signals — ";
    pp += "but still independently inspect key files.\n\n";
    pp += "Return hotspots (paths worth deep analysis), concrete signals (permissions, trust edges, dangerous APIs), ";
    pp += "risk_hint, and confidence 0-1.\n\n";
    pp += "<target-json>\n" + json_encode(tpath) + "\n</target-json>\n";
    pp += "<domain-hint-json>\n" + json_encode(domain) + "\n</domain-hint-json>\n";
    pp += "<profile-json>\n" + json_encode(profile) + "\n</profile-json>\n";
    pp += "<frozen-e-json>\n" + json_encode(e) + "\n</frozen-e-json>";

    let cap = "read-only";
    // allow execute for extension tooling / local CLI when profile is deep/paranoid
    if profile == "deep" || profile == "paranoid" || domain == "extension" {
        cap = "execute";
    }

    prelude_jobs.push(#{
        prompt: pp,
        label: "prelude-" + ti.to_string(),
        capability_mode: cap,
        output_schema: prelude_schema,
        phase: "Prelude",
    });
    ti += 1;
}
let prelude_results = parallel(prelude_jobs);

let surfaces = [];
let pi = 0;
for r in prelude_results {
    if r != () && r.success && r.output != () && r.output.target != () {
        surfaces.push(r.output);
    } else {
        // fail-open inventory stub so ranking still works
        let stub = #{
            target: targets[pi],
            kind: "unknown",
            surface_summary: "prelude agent failed or returned no schema output",
            hotspots: [],
            signals: [],
            risk_hint: "medium",
            confidence: 0.2,
            mythos_re_notes: "",
        };
        surfaces.push(stub);
        log("prelude failed for index " + pi.to_string());
    }
    pi += 1;
}
log("prelude complete: " + surfaces.len().to_string() + " surface map(s)");

// ============================================================================
// Phase: Rank — pick deep-dive set (depth extrapolation budget)
// ============================================================================
phase("Rank");
// Deterministic rank: critical>high>medium>low, then confidence
fn risk_rank(hint) {
    if hint == "critical" { 4 } else if hint == "high" { 3 } else if hint == "medium" { 2 } else if hint == "low" { 1 } else { 0 }
}

// simple selection sort by (risk, confidence)
let ranked = [];
for s in surfaces { ranked.push(s); }
let n = ranked.len();
let a = 0;
while a < n {
    let best = a;
    let b = a + 1;
    while b < n {
        let rb = risk_rank(ranked[b].risk_hint);
        let rbest = risk_rank(ranked[best].risk_hint);
        let cb = ranked[b].confidence;
        let cbest = ranked[best].confidence;
        if rb > rbest || (rb == rbest && cb > cbest) {
            best = b;
        }
        b += 1;
    }
    if best != a {
        let tmp = ranked[a];
        ranked[a] = ranked[best];
        ranked[best] = tmp;
    }
    a += 1;
}

let deep_targets = [];
let di = 0;
for s in ranked {
    if di < deep_k {
        deep_targets.push(s);
        di += 1;
    }
}
if deep_targets.len() == 0 {
    complete(#{
        summary: "No targets available for deep analysis.",
        path: "",
        confirmed: [],
    });
}
log("deep-dive set: " + deep_targets.len().to_string() + " of " + surfaces.len().to_string());

// ============================================================================
// Phase: Recurrent — MoE experts looped with frozen-e reinjection
// ============================================================================
phase("Recurrent");

// Which experts activate per phase (sparse MoE routing analog)
fn experts_for_phase(ph) {
    if ph == "surface" {
        ["trust_boundaries", "supply_chain_config", "ipc_messaging"]
    } else if ph == "semantic" {
        ["authn_authz", "injection_deserialization", "ipc_messaging"]
    } else if ph == "hypothesis" {
        ["authn_authz", "injection_deserialization", "crypto_secrets", "trust_boundaries"]
    } else {
        // exploit_class: focus on highest-impact classes only
        ["authn_authz", "injection_deserialization", "trust_boundaries"]
    }
}

let candidate_findings = [];
let loop_t = 0;
while loop_t < max_loops {
    let ph = phase_name(loop_t);
    let active = experts_for_phase(ph);
    log("recurrent loop t=" + loop_t.to_string() + " phase=" + ph + " experts=" + active.len().to_string());

    let jobs = [];
    let ji = 0;
    for surf in deep_targets {
        for ex in active {
            let prompt = SAFETY + json_encode(scope_text) + SAFETY2 + "\n\n";
            prompt += "RECURRENT BLOCK (OpenMythos-style loop). You are expert module \"" + ex + "\" ";
            prompt += "at loop_t=" + loop_t.to_string() + " phase=" + ph + ".\n";
            prompt += "CRITICAL: The frozen input injection e (original surface facts) is re-injected below — ";
            prompt += "do not drift into speculative issues unsupported by e + code you re-read.\n";
            prompt += "Use tools to re-open the hottest paths and search for concrete bugs in YOUR specialty only.\n";
            prompt += "Specialty guide:\n";
            prompt += "- trust_boundaries: origin checks, externally_connectable, CORS, SSRF edges, sandbox escapes, confused deputy\n";
            prompt += "- authn_authz: auth bypass, IDOR, privilege escalation, token/session flaws, FGAP-style admin gaps\n";
            prompt += "- injection_deserialization: XSS, SQLi, command injection, template/SSTI, unsafe deserialize, eval\n";
            prompt += "- crypto_secrets: hard-coded secrets, weak crypto, JWT alg confusion, key handling\n";
            prompt += "- supply_chain_config: deps, CI secrets, misconfig, default creds, debug endpoints\n";
            prompt += "- ipc_messaging: extension message handlers, postMessage, native messaging, XPC/IPC auth\n\n";
            if ph == "surface" {
                prompt += "Phase surface: broad pattern scan + inventory of dangerous sinks/sources.\n";
            } else if ph == "semantic" {
                prompt += "Phase semantic: reconstruct trust flow and who can reach each sink; require path evidence.\n";
            } else if ph == "hypothesis" {
                prompt += "Phase hypothesis: propose specific fail conditions; try to refute your own hypothesis while gathering evidence.\n";
            } else {
                prompt += "Phase exploit_class: for real issues only, refine preconditions and impact. ";
                prompt += "Describe MINIMAL verification steps — not weaponization.\n";
            }
            prompt += "Return at most 6 findings with real evidence (file paths + quotes). ";
            prompt += "Set novel_hypothesis=true only if you have reason to believe this is not a well-known footgun restatement.\n";
            prompt += "Set halt_component=true if further loops on this expert/target are unlikely to add signal (ACT analog).\n\n";
            prompt += "<frozen-e-json>\n" + json_encode(e) + "\n</frozen-e-json>\n";
            prompt += "<surface-map-json>\n" + json_encode(surf) + "\n</surface-map-json>\n";
            prompt += "<prior-findings-count>" + candidate_findings.len().to_string() + "</prior-findings-count>";

            let cap2 = "read-only";
            if profile == "paranoid" || (profile == "deep" && (ex == "ipc_messaging" || ex == "trust_boundaries")) {
                cap2 = "execute";
            }

            jobs.push(#{
                prompt: prompt,
                label: "t" + loop_t.to_string() + "-" + ex + "-" + ji.to_string(),
                capability_mode: cap2,
                output_schema: findings_schema,
                phase: "Recurrent",
            });
            ji += 1;
        }
    }

    // Budget guard: if this panel would be huge, we still launch (caller sets agent_budget).
    let results = parallel(jobs);
    let new_count = 0;
    for r in results {
        if r != () && r.success && r.output != () && r.output.findings != () {
            for f in r.output.findings {
                // stamp loop metadata
                let item = f;
                // Rhai maps from schema are objects; we store as-is and attach via parallel arrays later
                candidate_findings.push(#{
                    finding: f,
                    loop_t: loop_t,
                    phase: ph,
                });
                new_count += 1;
            }
        }
    }
    log("loop " + loop_t.to_string() + " added " + new_count.to_string() + " candidate finding(s); total=" + candidate_findings.len().to_string());

    // Soft ACT: if a deep profile loop adds nothing, stop early
    if new_count == 0 && loop_t >= 1 {
        log("ACT early exit: no new findings at loop " + loop_t.to_string());
        loop_t = max_loops; // break
    } else {
        loop_t += 1;
    }
}

// Deduplicate by title+severity (lightweight)
let unique = [];
for c in candidate_findings {
    let f = c.finding;
    let title = "";
    let sev = "";
    if f.title != () { title = trimmed(f.title); }
    if f.severity != () { sev = trimmed(f.severity); }
    let dup = false;
    for u in unique {
        let ut = "";
        let us = "";
        if u.finding.title != () { ut = trimmed(u.finding.title); }
        if u.finding.severity != () { us = trimmed(u.finding.severity); }
        if ut == title && us == sev && title != "" {
            dup = true;
        }
    }
    if !dup && title != "" {
        unique.push(c);
    }
}
// Cap candidates entering verification
let MAX_VERIFY = 12;
let to_verify = [];
let ui = 0;
for u in unique {
    if ui < MAX_VERIFY {
        to_verify.push(u);
        ui += 1;
    }
}
if unique.len() > MAX_VERIFY {
    log("verification cap: " + unique.len().to_string() + " → " + MAX_VERIFY.to_string());
}

if to_verify.len() == 0 {
    let empty_report = "# Mythos Vuln Research Report\n\n";
    empty_report += "**Status:** No candidate findings survived recurrent analysis.\n\n";
    empty_report += "## Scope\n" + scope_text + "\n\n";
    empty_report += "## Targets\n";
    for t in targets {
        empty_report += "- `" + t + "`\n";
    }
    empty_report += "\n## Prelude surfaces\n";
    for s in surfaces {
        empty_report += "### " + s.target + " (" + s.risk_hint + ")\n";
        empty_report += s.surface_summary + "\n\n";
    }
    empty_report += "\n_Empty findings are valid after inspection; try profile=deep or higher max_loops._\n";
    let p = write_scratch_file("report.md", empty_report);
    complete(#{
        summary: "No candidate findings.",
        path: p,
        confirmed: [],
        surfaces: surfaces.len(),
    });
}

// ============================================================================
// Phase: Verify — adversarial fail-closed skeptics
// ============================================================================
phase("Verify");
let vjobs = [];
let vi = 0;
for item in to_verify {
    let f = item.finding;
    let vp = SAFETY + json_encode(scope_text) + SAFETY2 + "\n\n";
    vp += "ADVERSARIAL VERIFIER. Your job is to REFUTE the finding if possible. ";
    vp += "Set real=true ONLY with concrete evidence you independently re-read from the codebase. ";
    vp += "Missing evidence ⇒ real=false. Known footguns restated without a concrete reachable path ⇒ real=false or novelty=known_pattern.\n";
    vp += "Check: wrong severity, unreachable preconditions, mitigated by framework defaults, or hallucinated APIs.\n\n";
    vp += "<finding-json>\n" + json_encode(f) + "\n</finding-json>\n";
    vp += "<loop-meta>loop_t=" + item.loop_t.to_string() + " phase=" + item.phase + "</loop-meta>\n";
    vp += "<frozen-e-json>\n" + json_encode(e) + "\n</frozen-e-json>";

    vjobs.push(#{
        prompt: vp,
        label: "verify-" + vi.to_string(),
        capability_mode: "read-only",
        output_schema: verdict_schema,
        phase: "Verify",
    });
    vi += 1;
}
let verdicts = parallel(vjobs);

let confirmed = [];
let rejected = 0;
let vi2 = 0;
for v in verdicts {
    if v != () && v.success && v.output != () && v.output.real == true
        && v.output.evidence != () && trimmed(v.output.evidence) != "" {
        let base = to_verify[vi2];
        confirmed.push(#{
            finding: base.finding,
            loop_t: base.loop_t,
            phase: base.phase,
            verdict: v.output,
        });
    } else {
        rejected += 1;
    }
    vi2 += 1;
}
log("verify: " + confirmed.len().to_string() + " confirmed / " + rejected.to_string() + " rejected of " + to_verify.len().to_string());

// ============================================================================
// Phase: Coda — disclosure packages + minimal repros + report
// ============================================================================
phase("Coda");

let repros = [];
if confirmed.len() > 0 {
    let MAX_REPRO = 6;
    let rjobs = [];
    let ri = 0;
    for c in confirmed {
        if ri < MAX_REPRO {
            let f = c.finding;
            let rp = SAFETY + json_encode(scope_text) + SAFETY2 + "\n\n";
            rp += "CODA — RESPONSIBLE DISCLOSURE PACKAGE. Build a MINIMAL verification package for the vendor/bounty program.\n";
            rp += "Allowed repro_kind: static_proof | local_lab_repro | config_demo | unit_test_sketch.\n";
            rp += "FORBIDDEN: weaponized exploit chains, memory-corruption shells, mass scanners, malware droppers, ";
            rp += "or instructions targeting third-party production without authorization.\n";
            rp += "Include clear fix_recommendation. Prefer the smallest artifact that proves the bug class.\n\n";
            rp += "<confirmed-finding-json>\n" + json_encode(f) + "\n</confirmed-finding-json>\n";
            rp += "<verdict-json>\n" + json_encode(c.verdict) + "\n</verdict-json>";

            rjobs.push(#{
                prompt: rp,
                label: "repro-" + ri.to_string(),
                capability_mode: "read-only",
                output_schema: repro_schema,
                phase: "Coda",
            });
            ri += 1;
        }
    }
    let rres = parallel(rjobs);
    for r in rres {
        if r != () && r.success && r.output != () {
            repros.push(r.output);
        }
    }
}

// Synthesize markdown report
let report = "";
report += "# Mythos Vuln Research Report\n\n";
report += "Architecture: **OpenMythos RDT** (Prelude → Recurrent MoE loops → Coda)  \n";
report += "Reference: https://github.com/kyegomez/OpenMythos · local harness: `mythos_re`  \n";
report += "Profile: `" + profile + "` · loops: " + max_loops.to_string() + " · deep_k: " + deep_k.to_string() + "\n\n";
report += "## Authorization & scope\n\n";
report += "- **Authorized:** true (gate enforced)\n";
report += "- **Scope:** " + scope_text + "\n";
report += "- **Disclosure mode:** responsible — minimal verification repros only\n\n";

report += "## Targets (prelude)\n\n";
for s in surfaces {
    let conf = s.confidence;
    report += "### `" + s.target + "`\n";
    report += "- kind: " + s.kind + " · risk_hint: **" + s.risk_hint + "** · conf: " + conf.to_string() + "\n";
    report += "- " + s.surface_summary + "\n";
    if s.signals != () {
        report += "- signals: ";
        let first = true;
        for sig in s.signals {
            if !first { report += "; "; }
            report += sig;
            first = false;
        }
        report += "\n";
    }
    report += "\n";
}

report += "## Deep-dive set\n\n";
for s in deep_targets {
    report += "- `" + s.target + "` (" + s.risk_hint + ")\n";
}
report += "\n";

report += "## Confirmed findings (" + confirmed.len().to_string() + ")\n\n";
if confirmed.len() == 0 {
    report += "_No findings survived adversarial verification (fail-closed). Review rejected candidates in the run log or re-run with profile=deep._\n\n";
} else {
    let fi = 1;
    for c in confirmed {
        let f = c.finding;
        let title = "";
        let sev = "";
        let cat = "";
        let rc = "";
        let ev = "";
        let imp = "";
        if f.title != () { title = f.title; }
        if f.severity != () { sev = f.severity; }
        if f.category != () { cat = f.category; }
        if f.root_cause != () { rc = f.root_cause; }
        if f.evidence != () { ev = f.evidence; }
        if f.impact != () { imp = f.impact; }
        report += "### " + fi.to_string() + ". [" + sev + "] " + title + "\n\n";
        report += "- **Category:** " + cat + "\n";
        report += "- **Root cause:** " + rc + "\n";
        report += "- **Impact:** " + imp + "\n";
        report += "- **Evidence:** " + ev + "\n";
        if c.verdict != () {
            let nov = "";
            let fix = "";
            if c.verdict.novelty != () { nov = c.verdict.novelty; }
            if c.verdict.fix_hint != () { fix = c.verdict.fix_hint; }
            report += "- **Novelty (verifier):** " + nov + "\n";
            if fix != "" {
                report += "- **Fix hint:** " + fix + "\n";
            }
        }
        report += "- **Discovered at:** loop " + c.loop_t.to_string() + " / phase " + c.phase + "\n\n";
        fi += 1;
    }
}

report += "## Disclosure packages (minimal verification)\n\n";
if repros.len() == 0 {
    report += "_No disclosure packages generated._\n\n";
} else {
    for r in repros {
        let id = "";
        let dt = "";
        let ek = "";
        let exp = "";
        let fix = "";
        if r.finding_id != () { id = r.finding_id; }
        if r.disclosure_title != () { dt = r.disclosure_title; }
        if r.repro_kind != () { ek = r.repro_kind; }
        if r.expected_result != () { exp = r.expected_result; }
        if r.fix_recommendation != () { fix = r.fix_recommendation; }
        report += "### " + dt + "\n\n";
        report += "- finding_id: `" + id + "` · repro_kind: `" + ek + "`\n";
        report += "**Steps:**\n";
        if r.steps != () {
            let sn = 1;
            for step in r.steps {
                report += sn.to_string() + ". " + step + "\n";
                sn += 1;
            }
        }
        report += "\n**Expected:** " + exp + "\n\n";
        report += "**Fix:** " + fix + "\n\n";
        if r.minimal_artifact != () && trimmed(r.minimal_artifact) != "" {
            report += "```\n" + r.minimal_artifact + "\n```\n\n";
        }
    }
}

report += "## Methodology (OpenMythos mapping)\n\n";
report += "| OpenMythos concept | This workflow |\n";
report += "|---|---|\n";
report += "| Prelude | Surface inventory + attack-surface map per target |\n";
report += "| Frozen input injection e | Scope + target list re-injected every expert prompt |\n";
report += "| Recurrent block + loop index | Multi-loop expert passes (surface→semantic→hypothesis→exploit_class) |\n";
report += "| Mixture of Experts | trust_boundaries, authn_authz, injection, crypto, supply_chain, ipc |\n";
report += "| ACT early exit | Stop deepening when a loop adds zero findings |\n";
report += "| Coda | Adversarial verify + disclosure packages + report |\n";
report += "| Depth extrapolation | Raise max_loops / deep_k / profile on hard targets |\n\n";

report += "## Operational notes\n\n";
report += "- Candidates entering verify: " + to_verify.len().to_string() + " (unique from recurrent)\n";
report += "- Confirmed: " + confirmed.len().to_string() + " · Rejected: " + rejected.to_string() + "\n";
report += "- Weaponized exploit generation is intentionally out of scope; packages are for responsible disclosure.\n";
report += "- For browser extensions, prefer local `mythos_re` static experts first, then this workflow for multi-target scale + LLM reasoning depth.\n";

let report_path = write_scratch_file("report.md", report);

// Also write machine-readable findings
let json_blob = json_encode(#{
    e: e,
    surfaces: surfaces,
    deep_targets: deep_targets,
    confirmed: confirmed,
    repros: repros,
    stats: #{
        candidates: to_verify.len(),
        confirmed: confirmed.len(),
        rejected: rejected,
        max_loops: max_loops,
        profile: profile,
    },
});
let json_path = write_scratch_file("findings.json", json_blob);

complete(#{
    summary: confirmed.len().to_string() + " confirmed findings across " + deep_targets.len().to_string() + " deep-dive target(s)",
    path: report_path,
    findings_path: json_path,
    confirmed_count: confirmed.len(),
    rejected_count: rejected,
    targets: targets.len(),
    deep_k: deep_targets.len(),
});
