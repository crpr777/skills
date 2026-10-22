---
name: "mythos-vuln-research"
description: "Deep iterative vulnerability research skill inspired by the OpenMythos Recurrent-Depth Transformer architecture. Uses a Prelude-Recurrent-Coda pipeline with MoE-style expert routing for exhaustive software and binary vulnerability analysis. Use this skill whenever the user asks for deep vulnerability research, iterative security auditing, binary analysis, source code vulnerability hunting, exploit surface mapping, multi-pass security review, or comprehensive vulnerability assessment of software targets. Also trigger when the user mentions \"deep dive\" security analysis, \"exhaustive\" vulnerability search, attack chain construction, or wants to find bugs that shallow scanning misses. Produces an interactive HTML artifact with sortable findings, attack graph visualization, and severity heatmap. Do NOT use for simple one-off CVE lookups, compliance checklists, or network scanning — this skill is for deep, iterative, compositional vulnerability reasoning against software targets."
---

# Mythos Vulnerability Research

A deep vulnerability research methodology modeled on the OpenMythos Recurrent-Depth
Transformer architecture. Instead of a single-pass review, this skill drives analysis
through three phases — **Prelude** (surface reconnaissance), a **Recurrent Block**
(iterative deep analysis with expert routing), and **Coda** (synthesis and reporting) —
producing findings that shallow analysis misses.

The core insight from looped transformers applies here: same analytical framework,
more iterations, deeper results. Each recurrent pass routes the target through
specialized expert modules (memory safety, logic bugs, crypto, auth, concurrency,
API boundaries), and each pass builds on the prior one's findings. Analysis halts
adaptively when passes stop yielding new findings (ACT-style convergence).

---

## The Pipeline

### Phase 1: PRELUDE — Surface Reconnaissance (Run Once)

The Prelude runs once to establish the encoded input `e` that gets injected into
every subsequent recurrent pass. This grounds all deep analysis in the actual
target, preventing drift.

**Steps:**

1. **Target Identification**
   - Determine target type: source code, binary, library, protocol, application
   - Identify language(s), framework(s), build system
   - Note the threat model: what's the deployment context? Who are the attackers?

2. **Attack Surface Enumeration**
   - Map all input vectors: files parsed, network protocols, IPC channels,
     user-controlled data, environment variables, config files
   - Identify trust boundaries: where does privilege change? Where does
     validated data meet unvalidated data?
   - Catalog external dependencies and their versions

3. **Architecture Decomposition**
   - Break the target into functional components/modules
   - Map data flow between components (what crosses boundaries?)
   - Identify security-critical paths: auth, crypto, access control,
     deserialization, memory management

4. **Initial Triage**
   - Flag high-value targets: parsers, deserializers, auth handlers,
     crypto implementations, IPC handlers, anything processing untrusted input
   - Prioritize by: attack surface exposure x historical bug density x impact

**Output of Prelude:** A structured target profile (`e`) containing:
- Component map with trust boundaries marked
- Prioritized list of analysis targets
- Input vector inventory
- Threat model summary

This profile is "injected" into every recurrent pass, keeping analysis
grounded in the actual target (analogous to the input injection `B·e` that
prevents hidden state drift in looped transformers).

---

### Phase 2: RECURRENT BLOCK — Iterative Deep Analysis (Looped T Times)

This is the core of Mythos-style analysis. A single analytical framework is
applied repeatedly, with each pass going deeper and building on prior findings.

**The recurrence rule (conceptual):**
```
findings_{t+1} = refine(findings_t) + inject(target_profile) + expert_analysis(findings_t, target)
```

Each pass routes through **expert modules** based on what the target needs
(MoE-style routing — not every expert fires on every pass).

#### Expert Modules (Route Based on Target)

| Expert               | Activates When                                    | Looks For                                           |
|----------------------|---------------------------------------------------|-----------------------------------------------------|
| Memory Safety        | C/C++/Rust unsafe, binary targets                 | Buffer overflows, UAF, type confusion, integer bugs |
| Logic & State        | State machines, auth flows, multi-step protocols   | TOCTOU, state confusion, logic bypasses, race conditions |
| Crypto & Auth        | Crypto usage, auth/session handling                | Weak algorithms, key mismanagement, auth bypasses   |
| Input Validation     | Any external input handling                        | Injection (SQL/cmd/LDAP), path traversal, deser bugs |
| Concurrency          | Threading, async, shared state                     | Data races, deadlocks, atomicity violations         |
| API & Interface      | IPC, RPC, REST, library APIs                       | Privilege confusion, API misuse, boundary violations |

**Expert Module Details:** Each expert module has detailed checklists covering specific vulnerability patterns, CWE mappings, and analysis techniques. The modules are:

**Memory Safety Expert** — Activates for C/C++/Rust unsafe/binary targets. Covers buffer overflows (CWE-120/122/787), use-after-free (CWE-416), type confusion (CWE-843), integer issues (CWE-190/191/681), double-free (CWE-415). Technique: trace all memory allocations from untrusted input, verify lifecycle (alloc→use→free), check arithmetic on sizes for overflow, verify bounds checks, audit error paths for double-free.

**Logic & State Expert** — Activates for state machines, auth flows, multi-step protocols. Covers TOCTOU/race conditions (CWE-367), state machine violations (CWE-841), logic bypasses (CWE-284), business logic flaws. Technique: map state machine (states+transitions+guards), check if guards can be bypassed or transitions happen out of order, verify all conditional branches including else/default cases.

**Crypto & Auth Expert** — Activates for crypto operations, authentication, session management. Covers weak cryptography (CWE-327/328), key management (CWE-321/798), auth weaknesses (CWE-287), token/session issues (CWE-384/613). Technique: inventory all crypto operations, check algorithms against current standards, trace key lifecycle, draw auth sequence diagrams looking for bypasses, check for timing oracles.

**Input Validation Expert** — Always activates for external input. Covers injection (CWE-89/78/90/917), path traversal (CWE-22), deserialization (CWE-502), format strings (CWE-134), XSS (CWE-79). Technique: taint analysis from entry to sink, verify validation exists between entry and sensitive usage, test validation bypasses (encoding, truncation, normalization), prefer allowlist over blocklist.

**Concurrency Expert** — Activates for threading, async, shared state. Covers data races (CWE-362), atomicity violations, signal handler issues (CWE-479), resource management races. Technique: identify all shared mutable state, verify synchronization, check lock ordering, look for TOCTOU gaps, audit signal handlers for safety.

**API & Interface Expert** — Activates for IPC, RPC, REST, library APIs. Covers privilege boundary confusion (CWE-269), API misuse (CWE-252/754), IPC vulnerabilities, REST/RPC issues (IDOR, mass assignment). Technique: map interface boundaries, verify auth/authz at each boundary, check callee validates all caller input, verify fail-open vs fail-closed behavior.

#### Loop Iteration Protocol

**Pass 1 — Pattern Matching (Surface Bugs)**
- Run all relevant expert modules at surface level
- Identify obvious vulnerability patterns (classic CWEs)
- Grep/search for known-bad patterns, dangerous function calls
- Flag: hardcoded secrets, dangerous defaults, missing checks
- This pass catches what a good static analyzer would catch

**Pass 2 — Compositional Analysis (Cross-Component Bugs)**
- Re-examine Pass 1 findings in context of data flow across components
- Trace tainted data from input vectors through to sensitive sinks
- Look for multi-step attack chains: bug A enables bug B
- Check: does component X trust component Y's output when it shouldn't?
- This pass catches what requires understanding multiple files together

**Pass 3 — Adversarial Reasoning (Novel Attack Synthesis)**
- Adopt attacker mindset: given what we know, what would we try?
- Construct attack chains from individual findings
- Look for semantic bugs: correct code that does the wrong thing
- Test assumptions: what if this "impossible" state IS reachable?
- Consider: supply chain angles, timing windows, error path abuse
- This pass catches what requires creative adversarial thinking

**Pass 4+ — Depth Extrapolation (Diminishing Returns Check)**
- Re-examine prior findings with fresh eyes
- Look for second-order effects: what does exploiting bug X unlock?
- Check for variant bugs: if pattern P was vulnerable here, where else?
- Probe edge cases in fixes/mitigations found during earlier passes

#### ACT-Style Convergence (When to Stop Looping)

After each pass, assess convergence:
- **Continue** if: new vulnerability classes discovered, unexplored
  components remain, attack chains are still being extended
- **Halt** if: pass yielded no new findings of medium+ severity,
  all prioritized components have been analyzed at depth,
  findings are variants of already-documented bugs

Minimum: 3 passes. Maximum: 6 passes. Most targets converge at 3-4.

#### Loop-Index Differentiation

Each pass operates differently despite using the same framework (analogous
to loop-index embeddings in OpenMythos):
- Pass 1: broad/shallow, pattern-matching mode
- Pass 2: narrow/deep, data-flow tracing mode
- Pass 3: creative/adversarial, attack synthesis mode
- Pass 4+: variant hunting, assumption testing mode

---

### Phase 3: CODA — Synthesis and Reporting (Run Once)

The Coda synthesizes all findings into the final deliverable.

**Steps:**

1. **Deduplicate and Consolidate**
   - Merge findings that describe the same underlying bug from different passes
   - Link related findings into attack chains
   - Remove false positives with clear justification

2. **Severity Scoring**
   - Assign CVSS 3.1 vector string to each finding
   - Map to CWE identifiers
   - Determine exploitability considering mitigations in place
   - Rank by: exploitability x impact x attack surface exposure

3. **Attack Chain Construction**
   - Build directed graphs: finding → enables → finding → achieves → impact
   - Identify the highest-impact chains
   - Note which chains require chaining multiple bugs vs single-bug exploitation

4. **Remediation Mapping**
   - For each finding: specific fix, not generic advice
   - Prioritize fixes by: chain-breaking value (fixing this one bug breaks N chains)
   - Note defense-in-depth opportunities

5. **Generate Interactive HTML Artifact**
   - Produce a self-contained HTML file (dark security-tooling theme, zero external dependencies) with:
     - **Findings table**: sortable by severity, CWE, component, pass discovered. Click row to expand detail panel with description, affected code, CVSS breakdown, PoC sketch, remediation.
     - **Attack graph**: SVG DAG with nodes as findings (colored by severity), edges showing "enables" relationships, left-to-right flow from entry points to impacts.
     - **Severity heatmap**: component (rows) x vulnerability class (columns) matrix. Cell color maps to finding count + max severity. Click cell to filter findings table.
     - **Statistics**: findings per pass bar chart (demonstrates iterative depth value), expert module activation chart, severity distribution, convergence curve showing diminishing returns.
   - Color scheme: Critical=#f85149, High=#f0883e, Medium=#d29922, Low=#58a6ff, Info=#8b949e
   - Dark theme: bg=#0d1117, text=#e6edf3, accent=#58a6ff
   - Embed all data as JS objects, all CSS inline, tab navigation between sections

---

## Conducting the Analysis

When a user invokes this skill:

1. Ask what the target is (if not already clear) and how they want to provide it
   (source code, binary path, GitHub URL, uploaded files, description)
2. Run the **Prelude** — build the target profile
3. Run the **Recurrent Block** — iterate through expert-routed passes, reporting
   brief progress after each pass ("Pass 2 complete: 3 new findings, continuing...")
4. Run the **Coda** — synthesize and build the artifact
5. Present the HTML artifact file to the user

For source code targets, use file tools (Read, Grep, Glob) extensively.
For binary targets, use the shell for `strings`, `objdump`, `file`, `xxd`,
and any available RE tools.
For descriptions/architecture reviews, reason from the provided information.

The key differentiator of this methodology is the iterative depth: findings from
Pass 1 inform Pass 2's data-flow analysis, which informs Pass 3's attack synthesis.
This compositional reasoning — the same property that makes looped transformers
powerful — is what catches bugs that single-pass reviews miss.

---

## Output Format

The primary output is an interactive HTML artifact. Additionally, produce a brief summary in chat covering:
- Total findings by severity (Critical / High / Medium / Low / Info)
- Top 3 most impactful attack chains
- Recommended priority fixes (chain-breakers first)
