# Breach and Credential Leakage Correlation

Methodology for correlating a target organization and its employees
against known breach corpuses, paste sites, code-leak monitors, and
search-indexed sensitive documents. Produces a list of confirmed
exposures, plausible reusable credentials, and exposed sensitive
materials that translate directly into initial-access vectors.

All techniques here use sources that are either public, free-research-
tier, or paid-research-tier services that the operator's organization
already subscribes to. No purchasing of stolen data, no scraping of
non-public closed-forum dumps, no participation in markets or channels
where the data flow itself is the harm.

## Table of Contents

1. Breach Database Correlation
2. Credential Reuse Inference
3. GitHub and Public Code Secret Leakage
4. Paste Site Historical Search
5. Search-Indexed Sensitive Documents
6. Open Storage and Misconfiguration
7. Severity Triage and Client Disclosure

---

## 1. Breach Database Correlation

### Free / public sources

- **Have I Been Pwned (HIBP)** — `haveibeenpwned.com/api/v3/`. Free for
  small-volume queries with API key. Supports lookup by email and by
  domain (the domain query is gated behind verified domain ownership,
  which is not appropriate for engagement use against a target — use
  per-email queries instead).
- **DeHashed** — paid; the canonical search tool for engagement-grade
  breach correlation. Operator's organization should already have a
  team license; if not, escalate before assuming use.
- **IntelX** (intelx.io) — paid; broader corpus than DeHashed for some
  document leaks and pastes.
- **LeakCheck.io** — paid alternative.
- **Snusbase** — paid alternative; has historically retained corpuses
  others have removed.
- **DDoSecrets** — public archive of leaked datasets, particularly
  useful for ransomware-aftermath data dumps.

For the engagement, the typical workflow is:

1. Query HIBP per email for breach history (free, fast, gives breach
   names and dates).
2. For confirmed-exposed employees, query DeHashed/IntelX for the
   actual leaked content (paid, slower, gives plaintext or hash data).
3. Correlate against engagement scope and severity criteria.

### Per-email schema

```json
{
  "email": "jane.smith@example.com",
  "breaches": [
    {
      "breach_name": "LinkedIn 2012",
      "breach_date": "2012-06",
      "data_classes": ["email", "passwords"],
      "password_format": "sha1_unsalted",
      "plaintext_recovered": true,
      "password_observed": "REDACTED_IN_DELIVERABLE",
      "source_ids": ["src-051"]
    }
  ],
  "reuse_likelihood": "high",
  "operational_notes": "Pattern matches employee's documented preference for word+year scheme"
}
```

In the deliverable JSON the literal password should be omitted; instead
record the hash, the cracked status, and the operator-internal location
where the plaintext is held under engagement-scoped storage.

### Domain-level signal

Even without per-email breach data, breach-frequency analysis at the
domain level signals organizational hygiene:

- A domain that appears in 30+ breaches over a decade reflects either
  high mention volume (large company) or chronic credential exposure
  (poor hygiene)
- A domain whose breach mentions cluster around recent dates suggests
  either a recent compromise of a vendor that held employee credentials
  or recent personal-account usage by employees
- A domain with no HIBP exposures at all is either very small, very new,
  or has invested in education to keep work email off third-party
  services

---

## 2. Credential Reuse Inference

A confirmed leaked password from a third-party breach is operationally
valuable only if the employee likely reused it for a target system.

### Reuse signals

- **The leaked password follows the company's documented complexity
  policy** — confirmed via help-text on the public password-reset page
  for the target's IdP. If the breach password from 2019 still meets
  the 2024 policy, it might still be in use.
- **Pattern repetition across multiple breaches for the same employee**
  — `Football2018!` and `Football2019!` and `Football2020!` across
  three breaches confirms a yearly-rotation scheme; the current-year
  variant is a high-probability target.
- **Personalization signal** — passwords containing the employee's
  birth year, alma mater, hometown, or family name (all available from
  social media) suggest a personal-pattern user.
- **Old password meets current corporate complexity rules and the
  employee has not visibly rotated identity since the breach** —
  highest-confidence reuse signal.

### Operational guardrails

- Validation of credentials against target systems is execution-phase
  activity, governed by the engagement's testing scope. The collection
  deliverable identifies *candidates*; it does not validate them.
- Before recording a password in any artifact, confirm engagement
  scope explicitly authorizes use of breach data. Some engagements
  scope-out breach data entirely.

---

## 3. GitHub and Public Code Secret Leakage

Building on tech-stack reference section 8, the credential-correlation
view focuses on what is operational *now*:

### Active credential discovery

- **Direct API key match in current HEAD** of a public repo — highest
  severity. Often still valid because rotation is rare absent detection.
- **API key in commit history but removed from HEAD** — frequently
  still valid, especially for keys not tied to detection systems.
- **API key in a forked repo** — often a developer's personal fork with
  test credentials that turned into production credentials over time.
- **Database connection strings** — `postgres://user:pass@host:5432/db`
  patterns. Frequently reveal internal hostnames and DNS naming
  conventions even if the password is rotated.

### Tooling

- **TruffleHog** (with `--only-verified` to filter to keys it could
  validate against the issuing service — these are the high-severity
  hits)
- **gitleaks** for broader regex-based scanning
- **GitGuardian** monitoring (paid, ongoing)
- **GitHub's own secret-scanning alerts** for repos owned by the target
  org — visible only to org members but referenced in security
  notification emails that sometimes leak in breach corpuses

### Schema

```json
{
  "secret_type": "AWS access key",
  "validity_status": "verified_active | likely_inactive | unknown",
  "repository": "github.com/.../repo",
  "first_committed": "2023-04-12",
  "still_in_head": true,
  "associated_account": {
    "service": "AWS",
    "account_id_or_handle": "123456789012",
    "permissions_inferred": ""
  },
  "operational_value": "",
  "client_notification_required": true,
  "source_ids": ["src-040"]
}
```

The `client_notification_required` flag exists because most engagement
contracts require prompt out-of-band notification for active credential
findings even before the report — these don't wait for the readout.

---

## 4. Paste Site Historical Search

Pastebin and its successors have hosted leaked credentials, source
snippets, and internal documents for two decades. Many original sites
have died, but historical archives persist.

### Sources

- **IntelX** (paid) — large historical paste corpus, searchable by
  domain, email, and string
- **Pastebin direct search** — current public pastes only; expires
  rapidly
- **psbdmp.ws** — historical Pastebin archive
- **Google `site:pastebin.com "<company>"`** — surfaces still-indexed
  public pastes
- **Wayback Machine snapshots of paste URLs** — when a paste was famous
  enough to be linked from elsewhere, the Wayback may have it

### What to search

- The target's primary domain
- The target's email format (e.g., `@example.com`)
- The target's product or codename strings
- Internal hostnames already discovered from CT logs or DNS

### Operational value

Pastes typically contain:

- Credential dumps from past breaches that were never indexed in
  formal breach databases
- "Check out this bug" disclosures that include internal URLs and
  sometimes session tokens
- Internal documents shared by departing employees ("I'm putting this
  here so I don't lose it")
- Source snippets that reveal architecture detail

---

## 5. Search-Indexed Sensitive Documents

Search engines index a lot of material that the publishing organization
did not intend to make public.

### Google dorks

The classic patterns still work:

- `site:example.com filetype:pdf "internal use only" OR "confidential"`
- `site:example.com filetype:xlsx`
- `site:example.com filetype:docx`
- `site:example.com inurl:admin`
- `site:example.com intitle:"index of"`
- `"<company>" filetype:pdf "do not distribute"` (search whole web,
  not just site:)
- `"<company>" filetype:csv` for leaked employee or customer lists
- `"<company>" filetype:sql` for leaked database dumps

### Cloud storage indexing

- `site:s3.amazonaws.com "<company>"`
- `site:storage.googleapis.com "<company>"`
- `site:blob.core.windows.net "<company>"`
- `site:firebaseio.com "<company>"`
- `site:azurewebsites.net "<company>"`
- `site:herokuapp.com "<company>"`

### Document-share platforms

- `site:scribd.com "<company>"`
- `site:slideshare.net "<company>"`
- `site:docs.google.com "<company>"` — public Google Docs that mention
  or contain the target
- `site:trello.com "<company>"` — public Trello boards
- `site:figma.com "<company>"` — public Figma files
- `site:notion.so "<company>"` — public Notion pages

### Source code aggregators

- `site:gitlab.com "<company>"`
- `site:bitbucket.org "<company>"`
- `site:gist.github.com "<company>"`
- `site:codepen.io "<company>"`

### Archive sites

- `site:archive.org "<company>" filetype:pdf`
- `site:scribd.com "<company>"`

### Recording

```json
{
  "url": "",
  "title": "",
  "source_platform": "",
  "filetype": "",
  "indexed_date": "",
  "still_accessible": true,
  "sensitivity": "high | medium | low",
  "rationale": "",
  "source_ids": ["src-061"]
}
```

---

## 6. Open Storage and Misconfiguration

Some categories of misconfiguration are discoverable purely by knowing
what to search for, with no probing of target infrastructure.

### S3 bucket misconfiguration

- **Grayhat Warfare** (`grayhatwarfare.com`) — searchable index of
  open S3 buckets
- **Public S3 listings** are returned by S3 itself when ACLs allow,
  which is observable from a single GET on the bucket root URL
- **Bucket name patterns** — try (in your notes only, do not enumerate
  against AWS): `<company>`, `<company>-prod`, `<company>-dev`,
  `<company>-staging`, `<company>-backup`, `<company>-logs`,
  `<company>-uploads`, `<company>-static`, `<company>-public`,
  `<company>-private`, `<company>-files`, `<company>-data`,
  `<company>-archive`. Operator judgement on which to actively check is
  governed by engagement scope.

### Azure Blob Storage

- Pattern: `<account>.blob.core.windows.net` with public containers
- Discovered through CT logs and through Grayhat-equivalent paid
  services that index Azure storage

### GCS

- Pattern: `storage.googleapis.com/<bucket>` with public access
- Discoverable through Google search and some paid index services

### Elasticsearch / MongoDB / Redis

- Historically discovered via Shodan and Censys passive scanning
- For engagement use, pivot from Shodan-confirmed candidate to the
  ownership question (does the IP belong to the target's announced
  ASNs, or to a third-party hosting provider used by the target)

---

## 7. Severity Triage and Client Disclosure

Not every leaked-data finding has the same operational status during
the engagement. Triage on three axes:

### Validity

- `verified_active` — the credential or asset is currently usable. For
  API keys this means the issuing service confirms the key (TruffleHog
  `--only-verified`). For accounts this means recent password-reuse
  signals are present.
- `likely_inactive` — the artifact is old enough or signal-poor enough
  that it is unlikely to be currently usable, but warrants documentation.
- `historical` — the artifact is informative but not currently usable.

### Severity

- `critical` — direct active credential to a high-impact system
  (production AWS, M365 admin, identity provider admin)
- `high` — active credential to a medium-impact system, or active
  credential whose blast radius is unclear
- `medium` — sensitive document with internal-only data, or credential
  whose validity is unverified
- `low` — informational findings (historical breach exposure with no
  active reuse signal, indexed-but-non-sensitive document)

### Engagement-contract notification triggers

Most engagement contracts contain language requiring prompt
out-of-band notification to the client when the operator discovers:

- Active credentials to production systems
- Active session tokens
- Sensitive customer data exposed to the public Internet
- Evidence of an existing third-party compromise (someone is already
  in)

For each finding flagged `verified_active` or `critical`, set
`client_notification_required: true` in the schema and ensure the
project lead is notified in real time. Do not wait for the readout.

### Schema

```json
{
  "id": "leak-007",
  "type": "breach_credential | leaked_secret | indexed_document | open_storage",
  "validity_status": "",
  "severity": "",
  "summary": "",
  "operational_use": "",
  "client_notification_required": false,
  "client_notified_at": null,
  "source_ids": []
}
```

---

## Output Integration

Breach-correlation feeds into the `leakage` block of `target_profile.json`:

```json
"leakage": {
  "breach_exposures": [/* per-email findings, schema in section 1 */],
  "leaked_secrets": [/* GitHub/code findings, schema in section 3 */],
  "indexed_documents": [/* search-indexed findings, schema in section 5 */]
}
```

And drives directly into the `entry_points` ranked synthesis — a
verified active credential is almost always a top-ranked entry point
under ATT&CK technique T1078 (Valid Accounts) with sub-techniques
specific to the credential type.
