# People Intelligence

Methodology for building the human map of a target organization. This
covers executive profiling, IT and security staff enumeration, recent-hire
and recent-departure targeting, organizational chart reconstruction from
public sources, and pretext-quality assessment for social engineering.

All techniques in this file are passive and rely on public or
publicly-accessible-with-account sources. No scraping that violates
platform terms beyond what an authenticated researcher would do
manually, no inducement of a target to disclose information.

## Table of Contents

1. LinkedIn as a Primary Source
2. Executive and Leadership Profiling
3. IT and Security Staff Enumeration
4. Recent Hires and Recent Departures
5. Organizational Chart Reconstruction
6. Conference and Speaking Circuit Mining
7. High-Value Target Selection
8. Pretext Quality Assessment

---

## 1. LinkedIn as a Primary Source

LinkedIn is the highest-yield single source for people intelligence on most
corporate targets. The following techniques work from a standard or Sales
Navigator account and stay within typical research-user behavior patterns.

### Search operators

LinkedIn's people search supports a small but powerful set of operators
when used in the keyword field:

- `"exact phrase"` — match an exact title or skill string
- `AND`, `OR`, `NOT` (uppercase, spaced) — boolean composition
- Parentheses for grouping: `(CISO OR "Chief Information Security Officer")`

Combine with the structured filters: Current company, Past company,
Location, Industry, School, Connections-of, Service categories.

### Useful canned searches

Replace `<Company>` with the target's name as it appears on its LinkedIn
company page (the "current company" filter resolves to that page, not a
free-text match).

- `"Chief Information Security Officer" OR CISO` filtered to Current
  company `<Company>`
- `helpdesk OR "service desk" OR "IT support"` filtered to Current company
  `<Company>`, then Sales Navigator can sort by tenure
- `(VP OR Director OR "Senior Manager") engineering` filtered to Current
  company `<Company>`
- `"executive assistant"` filtered to Current company `<Company>` —
  gatekeepers and high-trust phishing targets
- `recruiter OR talent` filtered to Current company `<Company>` —
  recruiters often share more about internal processes than other roles
- `intern OR "co-op"` filtered to Current company `<Company>` and posted
  in last 6 months — interns often have over-broad access and under-deep
  security training

### Recovering archived profiles

If a profile was deleted or made private after first observation, try in
order:

1. **Google Cache** — `cache:linkedin.com/in/<slug>` (cache life is short,
   so this only helps within days).
2. **Wayback Machine** — search `web.archive.org` for the profile URL.
   LinkedIn archive coverage is patchy but executives and conference-active
   employees are frequently captured.
3. **Bing cache** — sometimes retains pages Google has dropped.
4. **Email digest leak** — LinkedIn's own email notifications to first-
   degree connections sometimes preserve role/title at a point in time.

### Honoring platform reality

LinkedIn aggressively rate-limits and de-platforms suspicious activity.
For research-grade collection:

- Use a researcher account that looks like a researcher account — real
  profile photo, real history, real network. Burner accounts get flagged.
- Pace searches like a human. The platform tolerates dozens of profile
  views in a session; it does not tolerate hundreds in a minute.
- Don't auto-scrape. Document the queries you ran and the result counts;
  copy the relevant data manually. This is both safer for the account and
  produces better-curated data than wholesale scraping.

---

## 2. Executive and Leadership Profiling

### The mandatory roster

For any corporate target, build at minimum:

- **CEO** — face of the company, often impersonated in BEC, target of
  "CEO fraud" phishing
- **CFO** — wire-transfer authority, BEC target, often delegates to AP team
- **CIO** — technology authority, named in vendor case studies
- **CISO / Head of Security** — defender bench leader, may have public
  conference history that reveals tooling and program maturity
- **CTO** — engineering authority, often blogs/speaks publicly
- **General Counsel** — legal hold authority, rare but high-impact target
- **CHRO / Head of People** — HR phishing pretexts (benefits, payroll)
  ride on perceived authority from this office
- **Head of IT / VP Infrastructure** — operations authority, often quoted
  in vendor announcements

### Sources beyond LinkedIn

For each executive, enrich with:

- **SEC DEF 14A (proxy statement)** — for public companies, lists named
  executive officers with biographies, tenure, prior employers, board
  memberships, and total compensation. The biography is often the highest-
  fidelity source available.
- **Company "About" / "Leadership" page** — confirms current title and
  often reveals reporting structure not visible on LinkedIn.
- **Conference talk archives** — Black Hat, DEF CON, RSA, Gartner,
  industry-specific conferences. Speakers often disclose internal program
  detail (tools, team size, recent incidents).
- **Earnings call transcripts** (public companies) — names of executives
  who speak, often including non-NEO leaders like the head of a major
  business unit.
- **Patent filings** — co-inventors are usually current senior engineers.
- **Acknowledgments in published research / open source** — engineers and
  security staff appear in OSS commit logs and security advisory credits.

### Recording schema

For each executive, capture:

```json
{
  "name": "",
  "title": "",
  "tenure_at_target": "",
  "prior_employers": [],
  "linkedin_url": "",
  "public_appearances": [],
  "notable_quotes_or_disclosures": [],
  "social_media": {"twitter_x": null, "github": null, "personal_site": null},
  "source_ids": []
}
```

---

## 3. IT and Security Staff Enumeration

This is often more operationally valuable than the executive bench.
IT and security staff are:

- Targets of impersonation in vishing ("Hi, I'm from the helpdesk")
- Targets of phishing because they have privileged access
- Sources of leaked tooling information via job postings, GitHub, and
  conference talks

### Roles to enumerate

Build coverage across:

- **Helpdesk / service desk / IT support** — the impersonation surface
- **Sysadmins / Windows admins / Linux admins** — privileged access
- **Network engineers / network operations** — perimeter knowledge
- **SOC analysts / detection engineers** — defender capability
- **Identity and access management** — SSO/MFA configuration knowledge
- **Cloud / DevOps / SRE** — cloud footprint and CI/CD access
- **Application security / product security** — internal tooling knowledge
- **GRC / compliance** — process knowledge useful for pretexts

### Tool fingerprinting from staff profiles

Skills sections, certifications, and current job descriptions on LinkedIn
profiles routinely reveal:

- EDR vendor (CrowdStrike Certified, SentinelOne admin, Defender for
  Endpoint engineer)
- SIEM vendor (Splunk Certified, Sentinel engineer, Elastic certified)
- Identity stack (Okta admin, Azure AD engineer, CyberArk SME, BeyondTrust)
- Cloud (AWS SAA/SAP, Azure AZ-104/AZ-500, GCP PCA)
- Ticketing/ITSM (ServiceNow, Jira Service Management)
- SOAR/orchestration (Tines, Cortex XSOAR, Torq)

Aggregate across the team — if 8 of 12 SOC analysts list Splunk and 0
list Sentinel, that's a confirmed Splunk environment.

---

## 4. Recent Hires and Recent Departures

### Recent hires (last 30-90 days)

Recent hires are operationally golden because:

- They don't yet know internal communication norms
- They are still being added to systems and may receive legitimate-looking
  HR/IT setup emails (high cover for phishing lures)
- They're motivated to be helpful and responsive
- They often haven't completed security awareness training yet

LinkedIn surfaces these through:

- "Started a new position" activity in their feed
- The "Started new position" filter in Sales Navigator
- The activity feed of the company page (announcements often tag the new hire)

For each recent hire of operational interest, capture: name, role, start
date, prior employer, and whether they have publicly identified their
manager (often via their announcement post or first-week LinkedIn activity).

### Recent departures and layoffs

Layoffs and departures are useful as:

- Pretext seeds ("Following the recent restructuring, please confirm your
  benefits enrollment...")
- Impersonation candidates (a former employee's identity is plausible if
  IT hasn't fully revoked communication channels)
- Signals of internal disruption (overworked teams are less responsive)

Sources:

- **layoffs.fyi** — comprehensive tracker of tech-sector layoffs with
  confirmed counts and dates
- **LinkedIn "Open to Work" green ring** filtered to Past company
  `<Company>` and timeframe — proxy for involuntary departures at scale
- **WARN Act filings** (public, US) — required disclosures for mass
  layoffs at companies with 100+ employees
- **Press coverage** of restructurings, divestitures, and reorganizations

For each departure of operational interest, capture: name, last role,
approximate departure date, evidence of voluntary vs. involuntary, and
whether their LinkedIn still shows the target as current employer (a
delay-update-LinkedIn signal that the offboarding may be incomplete).

---

## 5. Organizational Chart Reconstruction

Even without an internal directory, a usable org chart can be reconstructed
from public sources. This matters for vishing (knowing who reports to whom
makes a "your manager asked me to call you" pretext credible) and for
spear-phishing (knowing the actual approver of an action makes a
spoofed-from-manager email plausible).

### Reconstruction sources

- **LinkedIn manager mentions** — employees often tag their manager when
  thanking them publicly, when posting about a team event, or when
  announcing a promotion ("Excited to be promoted by @Jane Smith")
- **Conference talk co-presenters** — co-presenters from the same company
  are usually on the same team or in a manager/report relationship
- **Patent co-inventors** — engineers on co-filed patents are frequently
  on the same team
- **GitHub commit graphs** — for organizations with public repositories,
  commit co-authorship and code review patterns reveal team structure
- **Press releases** — quotes typically come from a leader, with the
  named project owner credited; the relationship is usually direct
- **Internal job postings shared externally** — postings sometimes name
  the hiring manager

### Recording schema

Use a flat structure with parent references rather than nested trees:

```json
{
  "person_id": "p-014",
  "name": "Jane Smith",
  "title": "VP Engineering",
  "manager_person_id": "p-002",
  "team": "Platform",
  "confidence": "high",
  "evidence_source_ids": ["src-019", "src-022"]
}
```

This makes it trivial to render any subtree, query for spans of control,
or merge with later collection.

---

## 6. Conference and Speaking Circuit Mining

Public conference appearances by target employees are a high-yield source.

### Where to look

- **Black Hat / DEF CON** archives (talks, villages, workshops) — defender-
  side employees often reveal program detail
- **RSA Conference** archives — vendor-adjacent, but executive talks
  disclose strategy and budget priorities
- **Gartner Security Summit, IDC, Forrester** — leadership-level
  disclosures
- **BSides events** (regional) — engineers and analysts speak more
  candidly than at Black Hat
- **Industry-specific** — FS-ISAC for finance, H-ISAC for healthcare,
  E-ISAC for energy, EAS-ISAC for transportation
- **Vendor user conferences** — Splunk .conf, AWS re:Inforce, Microsoft
  Ignite, Okta Oktane. Customer talks at these events directly reveal
  the tool deployed and often the team running it.

### What to extract

For each talk:

- Speaker name and role at time of talk
- Tool/product/program disclosed
- Team size or program maturity statements
- Incidents or near-misses mentioned (some talks are public retros)
- Slides or recording URL (archive immediately — these get pulled)

---

## 7. High-Value Target Selection

Not every employee is a useful target. From the broader collection, mark
specific individuals as `high_value_targets` with a documented rationale.

### Criteria

A target is high-value if at least one applies:

- **Privileged access** — domain admins, cloud admins, identity admins
- **Wire-transfer authority** — CFO, treasurer, AP/AR managers, controllers
- **Code-signing or release authority** — release engineers, build owners
- **Recent hire AND privileged role** — perfect storm for phishing
- **Public-facing AND high-trust** — executive assistants, recruiters,
  PR/comms staff (will open unsolicited mail by job description)
- **Recently promoted** — workflow disruption + access expansion overlap
- **Known reuser of personal email** — visible in breach correlation

### Recording

For each HVT, record the rationale in plain language. The downstream
operator needs to be able to defend the targeting decision to the client
during the readout.

---

## 8. Pretext Quality Assessment

Before locking a target list, sanity-check the pretexts the data supports.
A pretext is high-quality when:

- The lure subject matches a real internal process (vendor onboarding,
  benefits open enrollment, expense report review, security training
  reminder)
- The sender identity matches a real role at the target (or a real
  vendor relationship the target has)
- The timing matches a real event window (post-acquisition integration,
  end of quarter, week before a public earnings call)
- The recipient profile matches who would normally receive this kind of
  message (recent hires get HR setup; AP gets invoices; engineers get
  GitHub notifications)

If all four hold, the pretext is `high quality`. If three hold, `medium`.
If fewer, reconsider — low-quality pretexts get reported, blow cover, and
typically don't even get the click.

---

## Output Integration

People-intel collection feeds directly into the `people` block of
`target_profile.json`:

```json
"people": {
  "executives": [/* one entry per leader, schema in section 2 */],
  "it_and_security_staff": [/* one entry per relevant tech employee */],
  "recent_hires": [/* one entry per hire in last 90 days */],
  "recent_departures": [/* one entry per departure of interest */],
  "high_value_targets": [/* one entry per HVT with rationale */]
}
```

Cross-reference each entry's `source_ids` to entries in the top-level
`sources` array of the profile.
