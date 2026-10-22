---
name: osint-target-profiling
description: >
  Advanced passive OSINT collection and target profiling for authorized red
  team engagements and adversary emulation. Use whenever the user asks to
  profile, scope, footprint, recon, or build an intelligence package on a
  target organization — including corporate structure, executive and IT/
  security staff identification, employee contact and email harvesting,
  LinkedIn data leakage, tech stack fingerprinting (DNS, TLS certs, GitHub,
  BuiltWith), credential and breach correlation, and ranked initial-access
  entry-point synthesis. Trigger on phrases like "OSINT on a company",
  "recon this target", "build a target profile", "pre-engagement intel",
  "scope the attack surface", "find phishing targets", or any request
  involving passive reconnaissance of an organization. Also trigger for red
  team scoping, threat actor emulation prep, social engineering pretext
  development, and vishing target research. Produces structured JSON and a
  narrative markdown dossier mapped to MITRE ATT&CK.
---

# OSINT Target Profiling

A structured methodology for building deep, passive intelligence packages on
target organizations during authorized red team and threat-led penetration
testing engagements. Produces both machine-readable JSON (for downstream
tooling and team handoff) and a narrative markdown dossier (for client
deliverable, scoping notes, or operator quick-reference).

## Engagement Boundaries

This skill operates exclusively within authorized engagement scope. Before
producing any output, the operator should confirm:

- A signed Statement of Work, Rules of Engagement, or equivalent authorization
  covers reconnaissance against the named target.
- Collection stays passive: no port scans, no service interaction with
  target-owned infrastructure, no credential testing, no active probing of
  third-party platforms beyond their normal user-facing functionality.
- Data handling complies with engagement contract — typically client data
  stays in encrypted operator workspace, breach data is referenced not
  redistributed, and PII is minimized in deliverables.

If the user has not confirmed scope, ask once before proceeding. If the
target is described as a personal grudge, an ex-employer with no SOW, an
unconsented party, or any other framing that suggests unauthorized activity,
decline and explain why. Authorized engagements are the default assumption
for security consultancy work — read context carefully.

## How to Use This Skill

1. **Start here** for the collection workflow, output schema, and ATT&CK mapping.
2. **Read `references/people-intel.md`** when working LinkedIn, executive
   profiling, helpdesk and IT staff enumeration, recent-hires and recent-departures
   targeting, or social engineering pretext development.
3. **Read `references/tech-stack.md`** when fingerprinting the target's
   technology footprint — DNS, certificate transparency, GitHub, BuiltWith,
   Shodan/Censys passive views, job-posting tech leakage, third-party SaaS
   inference.
4. **Read `references/contact-harvesting.md`** when working email format
   inference, role-based mailbox discovery, phone tree enumeration, or
   building target lists for phishing/vishing/smishing.
5. **Read `references/breach-correlation.md`** when correlating against HIBP,
   Dehashed-equivalent paid services, public breach corpuses, GitHub leak
   monitoring, or Pastebin/paste-site historical data.
6. **Use `scripts/`** for repeatable mechanical work (email permutation,
   certificate transparency queries, ATT&CK mapping, LinkedIn role parsing,
   subdomain consolidation).

The references are intentionally separated so the operator only loads what
the current phase of the engagement actually needs. For a fresh
pre-engagement profile, start with people-intel and tech-stack; pull in
contact-harvesting once the email format is inferred and you're building
target lists; pull in breach-correlation once you have a confirmed domain
and employee email pattern.

---

## Collection Workflow

### Phase 1: Corporate Footprint and Anchoring

Before touching anything else, establish the boundaries of the target
organization. This is the foundation that determines what counts as
in-scope downstream.

Pull from the following passive sources in order of authority:

- **Corporate registries** — SEC EDGAR (10-K, 10-Q, DEF 14A, 8-K filings list
  subsidiaries, executives, recent acquisitions, named auditors and law
  firms), Companies House (UK), state Secretary of State business filings,
  OpenCorporates for international structure, Crunchbase and PitchBook for
  funding history and investor relationships.
- **Trademark and IP** — USPTO TESS for trademark filings (reveals product
  brand names, internal codenames, design firms), Google Patents for
  technology and inventor names (often current senior engineers).
- **Domain ownership** — historical WHOIS via DomainTools or WhoisXML,
  registrar patterns, email contacts in unredacted historical records,
  registrant org name variations that reveal subsidiaries or rebrands.
- **News and PR** — vendor and customer announcements (case studies are gold:
  "Company X chose Vendor Y to solve Z" tells you the tech stack and the
  business problem), press releases for office openings/closings, earnings
  call transcripts for technology and personnel mentions.

Anchor outputs:

- Primary domain(s) and confirmed subsidiary/brand domains
- Subsidiary and DBA list with corporate hierarchy
- Office locations with address, approximate headcount where inferable, and
  function (HQ, R&D, manufacturing, datacenter, satellite sales)
- Key business relationships (customers cited in case studies, named
  vendors, named MSPs/MSSPs, named auditors and outside counsel)

### Phase 2: People Intelligence

Build the human map. The depth needed depends on engagement type — for a
phishing-led test you want a wide net of targetable employees; for a
physical or vishing-heavy engagement you want depth on a smaller set of
high-value or high-access individuals.

Reference: `references/people-intel.md` for full methodology including
LinkedIn search operators, archived-profile recovery, organization chart
reconstruction from public conference talks, and recent-hire targeting.

Anchor outputs:

- Executive roster (CEO, CFO, CIO, CISO, CTO, GC, CHRO at minimum) with
  tenure, prior employers, public conference appearances, public statements
- IT and security staff (helpdesk lead, sysadmins, network engineers, SOC
  analysts, security engineers, identity team, cloud team) — these are
  prime targets for both impersonation (in vishing) and direct phishing
- Recent hires (LinkedIn "started a new position" within last 90 days) —
  unfamiliar with internal norms, prime phishing demographic
- Recent departures and layoffs — useful for impersonation pretexts and as
  a signal of internal disruption
- Executive assistants and office managers — gatekeepers in vishing,
  high-trust phishing recipients

### Phase 3: Technology Stack Fingerprinting

Build the technical map. Stay passive — read public DNS, certificate
transparency logs, public GitHub, archived job postings, public vendor case
studies. Do not actively probe target infrastructure.

Reference: `references/tech-stack.md` for DNS enumeration techniques, CT log
querying, GitHub dorking, BuiltWith/Wappalyzer methodology, job posting
mining, and SaaS inference patterns.

Anchor outputs:

- Subdomain inventory from CT logs, passive DNS, and archive sources
- Inferred edge stack (CDN, WAF, MX provider, SPF/DMARC records as published)
- Inferred identity stack (Okta/Azure AD/Ping/Duo discoverable via login
  redirects, federation domains, public app catalog)
- Inferred SaaS footprint (Workday, ServiceNow, Salesforce, Slack, Atlassian,
  Box, Dropbox, GitHub Enterprise — most leak via DNS, headers, or job posts)
- Inferred endpoint and EDR (job postings naming Crowdstrike/SentinelOne/
  Defender/etc., GitHub repos referencing tooling)
- Public code repositories with internal references, secrets, or
  infrastructure metadata
- Cloud footprint (AWS account IDs from public S3 buckets, Azure tenant IDs
  from login pages, GCP project IDs from public storage)

### Phase 4: Contact and Communication Surface

Map the channels an attacker can reach the organization through.

Reference: `references/contact-harvesting.md` for email format inference,
role-based mailbox enumeration, phone tree mapping, and target-list
construction.

Anchor outputs:

- Confirmed email format(s) — primary and any legacy patterns
- Targetable employee email list with confidence ratings (confirmed vs.
  inferred-from-format)
- Role-based mailboxes (info@, hr@, security@, helpdesk@, vendor@, ap@)
- Public phone numbers including direct-dial extensions where leaked
- Social media presence per executive and per corporate brand

### Phase 5: Credential and Data Leakage

Correlate against breach data, paste sites, and code-leak monitoring.

Reference: `references/breach-correlation.md` for HIBP-class queries,
GitHub leak hunting, paste site historical search, and combo-list
correlation.

Anchor outputs:

- Confirmed breach exposures by employee email (which breaches, what data
  classes, dates)
- Likely-still-valid credentials inferred from password reuse signals
- Leaked secrets from public repositories (API keys, internal hostnames,
  config files committed to public forks)
- Sensitive documents indexed by search engines (filetype:pdf,
  filetype:xlsx, S3 bucket listings, exposed Google Drive shares)

### Phase 6: Synthesis — Ranked Entry Points

This is where intelligence becomes operational. Translate findings into a
ranked list of plausible initial access vectors, mapped to MITRE ATT&CK.

For each candidate vector, score on:

- **Plausibility** — how realistic is this given what we found?
- **Pretext quality** — how convincing can we make the lure or impersonation?
- **Detection risk** — what's the likely defender visibility on this path?
- **Effort** — how much development before we can execute?

Map each vector to the ATT&CK technique(s) it implements. Common output:

- Spear-phishing (T1566.001/.002/.003) targeting recent hires with HR-themed
  lure given inferred Workday/UKG presence
- Vishing (T1566.004) impersonating helpdesk to capture MFA-fatigue or
  push-bombing target list
- Drive-by compromise (T1189) targeting watering holes inferred from
  vendor/partner relationships
- External remote services abuse (T1133) against inferred VPN/SSO endpoint
- Valid accounts via leaked credentials (T1078) where breach correlation
  produced plausible reusable creds
- Supply chain (T1195) via named third-party vendors and MSPs

---

## Output Format

Produce two artifacts in the same engagement folder:

### 1. `target_profile.json` — Structured Intelligence Package

Use this exact top-level shape so downstream tooling and the team's existing
parsers can consume it:

```json
{
  "target": {
    "primary_name": "",
    "primary_domain": "",
    "aliases": [],
    "subsidiaries": [],
    "headquarters": "",
    "industry": "",
    "employee_count_estimate": null,
    "revenue_estimate_usd": null,
    "engagement_id": "",
    "collected_at": "",
    "collected_by": ""
  },
  "corporate_footprint": {
    "locations": [],
    "leadership_roster": [],
    "named_relationships": {
      "auditor": null,
      "outside_counsel": null,
      "msp_or_mssp": [],
      "named_customers": [],
      "named_vendors": []
    },
    "recent_events": []
  },
  "people": {
    "executives": [],
    "it_and_security_staff": [],
    "recent_hires": [],
    "recent_departures": [],
    "high_value_targets": []
  },
  "tech_stack": {
    "domains_and_subdomains": [],
    "edge": {"cdn": null, "waf": null, "dns": null},
    "email": {"mx": null, "spf": null, "dmarc": null, "dkim_observed": []},
    "identity": {"idp": null, "mfa": null, "federation": []},
    "saas": [],
    "endpoint_and_edr": [],
    "cloud": {"aws": [], "azure": [], "gcp": []},
    "code_repositories": []
  },
  "contact_surface": {
    "email_format": "",
    "email_format_confidence": "",
    "harvested_emails": [],
    "role_mailboxes": [],
    "phone_numbers": []
  },
  "leakage": {
    "breach_exposures": [],
    "leaked_secrets": [],
    "indexed_documents": []
  },
  "entry_points": [
    {
      "rank": 1,
      "vector": "",
      "attack_technique": [],
      "narrative": "",
      "plausibility": "",
      "pretext_quality": "",
      "detection_risk": "",
      "effort": "",
      "supporting_findings": []
    }
  ],
  "sources": []
}
```

Every claim in the profile should be traceable to an entry in `sources`,
which uses the shape:

```json
{
  "id": "src-001",
  "type": "linkedin | sec_filing | ct_log | github | press | breach_index | ...",
  "url": "",
  "retrieved_at": "",
  "notes": ""
}
```

Inline citations in other sections reference `source_ids: ["src-001",
"src-014"]`.

### 2. `target_dossier.md` — Narrative Deliverable

The markdown dossier walks the same content in a form suitable for a
team handoff or client-facing scoping appendix. Use this exact structure:

```markdown
# Target Profile: <Organization>
**Engagement:** <ID> | **Collected:** <date> | **Operator:** <name>

## 1. Executive Summary
3-5 sentences. Who is the target, what is their attack surface in broad
strokes, and what are the top 2-3 entry points the rest of the document
will defend.

## 2. Corporate Footprint
Locations, structure, leadership at a glance, named third-party relationships.

## 3. People Intelligence
Executive bench, IT/security staff, recent hires, recent departures,
high-value targets with rationale.

## 4. Technology Stack
Edge, identity, SaaS, endpoint, cloud, code. Use a table where helpful but
keep prose between tables.

## 5. Contact Surface
Email format, sample target list, role mailboxes, phone tree summary.

## 6. Data Leakage
Breach exposures, leaked secrets, indexed documents — with severity per item.

## 7. Ranked Entry Points
Numbered list. Each entry: vector, ATT&CK mapping, narrative pretext, why
it works given the intel above.

## 8. Sources
Numbered list with URL and retrieval date for every source cited.
```

Keep prose dense and operational — this document is read by people who are
either preparing to execute or briefing the client. No filler.

---

## Operating Principles

**Passive only, throughout.** No active probing of target infrastructure.
DNS lookups against public resolvers and CT log queries are passive. Sending
crafted requests to target-owned web apps, scanning ports, or attempting
authentication is not — those go in execution phases under a different
authorization scope.

**Source every claim.** A target dossier with unsourced assertions is worse
than one with gaps. If a finding cannot be sourced, mark it `inferred` with
the reasoning trail.

**Confidence, not certainty.** Use a small fixed vocabulary: `confirmed`
(direct evidence in primary source), `high` (consistent with multiple
secondary sources), `medium` (inference from one strong signal),
`low` (working hypothesis). Don't invent precision the data doesn't support.

**Minimize PII in deliverables.** Employee names and titles are operational
necessities; home addresses, family members, and personal identifiers are
not. Redact unless the engagement scope explicitly requires them and the
client has authorized.

**Refresh on cadence.** OSINT is perishable. Note the collection date on
every artifact, and for engagements lasting more than 30 days, refresh
people-intel and breach-correlation sections before execution begins.

**Use the helper scripts** in `scripts/` for the mechanical work. They are
faster, more consistent, and produce output that drops directly into the
JSON schema.

---

## Helper Scripts

Located in `scripts/`. Run from the skill directory or copy to the
engagement workspace.

- `email_permutator.py` — Generate likely email addresses from name lists
  and a target domain, supporting the common formats. Outputs into the
  `harvested_emails` schema shape.
- `ct_query.py` — Query crt.sh for certificate transparency entries on a
  target domain and dump unique subdomains. Outputs into the
  `domains_and_subdomains` schema shape.
- `linkedin_role_parser.py` — Parse a pasted LinkedIn search result block
  into a structured roster, classifying each entry into the `executives`,
  `it_and_security_staff`, `recent_hires`, or `recent_departures` buckets
  based on title heuristics.
- `attack_mapper.py` — Map free-text entry-point descriptions to the most
  plausible MITRE ATT&CK techniques using a built-in keyword lookup.
- `dossier_render.py` — Render `target_profile.json` into the
  `target_dossier.md` format using the structure above.

Each script has a `--help` flag and reads/writes JSON consistent with the
schema in this document.

---

## Quick Reference: Common Source-to-Finding Mapping

When time is short and you need to know which source answers which question:

| Need to find                  | Best passive source                                  |
|-------------------------------|------------------------------------------------------|
| Subsidiary list               | SEC 10-K Exhibit 21, OpenCorporates                  |
| Executives and tenure         | Proxy statement (DEF 14A), LinkedIn, company "About" |
| Recent hires                  | LinkedIn "started a new position" filter             |
| Layoffs / recent departures   | layoffs.fyi, LinkedIn "open to work" cohort, news    |
| Email format                  | hunter.io, RocketReach (read-only views), press     |
| Subdomains                    | crt.sh, certspotter, SecurityTrails passive DNS      |
| Tech stack from job posts     | LinkedIn jobs, company careers page, BuiltIn         |
| Cloud footprint hints         | Public S3 listings, Azure AD getuserrealm responses  |
| EDR / endpoint vendor         | Job posting tool requirements, GitHub repos          |
| MSSP / MSP                    | Press releases, case studies on vendor sites         |
| Leaked credentials            | HIBP (free), Dehashed/IntelX (paid), DDoSecrets      |
| Leaked secrets in code        | GitHub code search, TruffleHog scans of public forks |
| Indexed sensitive docs        | Google dorks (filetype:, site:, intitle:)            |
| Phone tree / extensions       | Archived "contact us" pages on Wayback, news quotes  |
| Office locations              | SEC filings, LinkedIn, Google Maps, news             |
| M&A and divestitures          | 8-K filings, Crunchbase, news                        |

For deeper guidance on any row, see the matching reference file.
