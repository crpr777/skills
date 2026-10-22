# Technology Stack Fingerprinting

Methodology for building the technical map of a target organization
through passive sources only. Covers DNS and certificate transparency,
GitHub reconnaissance, web technology fingerprinting, job-posting tech
mining, and SaaS inference.

No active probing of target infrastructure. Public DNS resolvers,
certificate transparency logs, public code repositories, public job
boards, and authenticated reads of public-facing services count as
passive. Sending crafted requests, port scans, vulnerability scans, or
authentication attempts against target systems do not.

## Table of Contents

1. Domain and Subdomain Enumeration
2. Certificate Transparency
3. Email and DNS Records
4. Identity Provider and Federation Discovery
5. SaaS Footprint Inference
6. Endpoint and EDR Inference
7. Cloud Footprint Discovery
8. GitHub and Public Code Reconnaissance
9. Web Technology Fingerprinting
10. Job Postings as a Tech Disclosure Source

---

## 1. Domain and Subdomain Enumeration

### Anchor domain discovery

Start from the primary corporate domain, then expand:

- **WHOIS history** (DomainTools, WhoisXML, ViewDNS) — historical
  registrant records frequently link sister domains owned by the same
  entity even after privacy was applied.
- **Reverse WHOIS** by registrant org name or email — pulls every domain
  registered to that entity.
- **Trademark filings** (USPTO) — brand names that may map to additional
  domains.
- **Securities filings** — exhibits in 10-K filings and merger documents
  list trade names and brand subsidiaries.
- **Employee bio domains** — executives often own personal domains; not
  in scope for the engagement, but may pivot to corporate domains during
  research.

### Subdomain enumeration (passive)

Use these in combination — no single source is comprehensive:

- **crt.sh** — free certificate transparency search by domain (use the
  `?q=%25.example.com` URL form for wildcards). Highest yield single source.
- **certspotter** (`https://api.certspotter.com/v1/issuances?domain=example.com`)
  — comparable to crt.sh, sometimes returns entries crt.sh has not yet
  indexed.
- **Censys / Shodan** — passive views over previously-collected scan data.
  Free tiers are limited; paid tiers reveal historical certificate and
  banner data.
- **SecurityTrails / DNSDumpster** — passive DNS, includes historical A
  records.
- **Wayback Machine** CDX API (`http://web.archive.org/cdx/search/cdx?url=*.example.com`)
  — surfaces subdomains that were once linked from public pages.
- **Google / Bing dorks** — `site:example.com -site:www.example.com` to
  find subdomains indexed by search.

The bundled `scripts/ct_query.py` wraps crt.sh with deduplication and
the JSON schema shape.

### Recording

```json
{
  "hostname": "vpn.example.com",
  "first_seen": "2019-04-12",
  "last_seen": "2025-11-03",
  "source": "crt.sh",
  "interesting": true,
  "interest_reason": "VPN gateway naming convention; potential remote access",
  "source_ids": ["src-031"]
}
```

Mark entries as `interesting: true` for hostnames that imply attacker-
relevant infrastructure: VPN gateways, mail relays, dev/staging/test,
admin panels, login portals, file-share endpoints, monitoring portals,
CI/CD endpoints.

---

## 2. Certificate Transparency

Beyond subdomain discovery, CT logs reveal:

- **Internal naming conventions** — `corp.example.com`, `ad.example.com`,
  `int.example.com`, `dev.example.com`
- **Recent rollouts** — newly-issued certs for previously-unseen hostnames
  signal new applications coming online
- **Cloud migration signals** — certs issued by AWS Certificate Manager,
  Google Trust Services, Azure-issued certificates correlate with cloud
  service deployment
- **Vendor relationships** — certs issued for `tenant.vendor.com`-style
  hostnames reveal SaaS vendors in use
- **Rotational hygiene** — short-lived (Let's Encrypt) vs long-lived
  certs reveal automation maturity
- **Co-issued SANs** — a single certificate covering 80 hostnames is
  effectively a full subdomain dump

Query strategies:

- By domain wildcard: `%.example.com`
- By organization name in the certificate Subject: useful for self-signed
  patterns
- By sponsoring CA: filtering for AWS-issued certs reveals AWS-hosted
  services
- By issuance date range: tracking what's new since last collection

---

## 3. Email and DNS Records

A few DNS records are particularly information-rich:

### MX

The MX record reveals the email provider:

- `*.outlook.com` → Microsoft 365
- `*.google.com` / `*.googlemail.com` → Google Workspace
- `*.pphosted.com` / `*.proofpoint.com` → Proofpoint email security gateway
  (still routes to M365 or GWS underneath in most cases)
- `*.mimecast.com` → Mimecast email security gateway
- `*.barracudanetworks.com` → Barracuda
- Self-hosted on company-owned MX → on-prem Exchange or similar (rarer
  but operationally significant)

### SPF (TXT, `v=spf1`)

The SPF record enumerates every domain authorized to send mail as the
target. This is a free SaaS catalog: each `include:` reveals a vendor.

Common include patterns:

- `_spf.google.com` → Google Workspace
- `spf.protection.outlook.com` → Microsoft 365 Exchange Online
- `_spf.salesforce.com` → Salesforce
- `_spf.mailgun.org` / `mailgun.com` → Mailgun
- `sendgrid.net` → SendGrid (often Twilio account behind it)
- `_spf.intercom.io` → Intercom
- `_spf.marketo.com` → Marketo (often Adobe Experience Cloud)
- `_spf.pardotemail.com` → Pardot (Salesforce Marketing)
- `mktomail.com` → Marketo
- `_spf.zendesk.com` → Zendesk
- `_spf.workday.com` → Workday (HR/payroll communications)
- `_spf.atlassian.net` → Atlassian
- `_spf.slack.com` → Slack
- `pphosted.com` → Proofpoint

### DMARC (TXT at `_dmarc.example.com`)

Reveals enforcement posture and reporting endpoints:

- `p=none` → reporting only, no enforcement (spoofable)
- `p=quarantine` → some enforcement, partial spoof protection
- `p=reject` → strict enforcement, BEC harder
- `rua=mailto:dmarc@vendor.com` → DMARC analytics vendor (Valimail, Dmarcian,
  Agari, Red Sift, Easy DMARC)

### DKIM

DKIM selectors are public and discoverable: `<selector>._domainkey.example.com`.
Common selectors leak vendor identity:

- `google._domainkey` → Google Workspace
- `selector1._domainkey`, `selector2._domainkey` → Microsoft 365
- `mta1._domainkey`, `mta2._domainkey` → various
- `s1._domainkey` named after a vendor → that vendor signs mail

If you observed a vendor in SPF, the matching DKIM selector confirms it.

### Subdomain TXT records

`_dmarc`, `_acme-challenge`, vendor-specific verification TXT records
(`google-site-verification`, `MS=`, `atlassian-domain-verification`,
`facebook-domain-verification`, `apple-domain-verification`) all reveal
vendor relationships.

---

## 4. Identity Provider and Federation Discovery

### Microsoft 365 / Entra ID

Entra ID exposes a public endpoint that reveals federation state:

```
https://login.microsoftonline.com/getuserrealm.srf?login=<probe>@example.com&xml=1
```

The response indicates:

- `NameSpaceType=Managed` → Entra ID native authentication
- `NameSpaceType=Federated` → federated to an external IdP (look at
  `AuthURL` for the IdP host — ADFS, Okta, Ping, etc.)
- `NameSpaceType=Unknown` → domain not in Entra ID

Use a *non-targeted* probe (a clearly fake username at the domain) to
avoid triggering account lockout or alerting. This endpoint does not
authenticate; it tells you about the tenant configuration.

The tenant ID can also be retrieved from:
```
https://login.microsoftonline.com/<domain>/.well-known/openid-configuration
```

### Okta

If Okta is the IdP, the tenant typically lives at `<company>.okta.com` or
`<company>.oktapreview.com`. Common discoverable signals:

- Federation chains observed in `getuserrealm` responses
- Subdomain enumeration revealing `okta.example.com` or
  `<company>.okta.com` (CT logs)
- Press release announcements of Okta deployment

### Login portal fingerprinting

Hitting the public login page (which is an unauthenticated public
resource — passive) reveals:

- Branding telltale of the IdP behind a custom domain
- MFA factors offered (SMS, push, FIDO2, voice — reveals security
  maturity)
- Self-service password reset behavior (some flows leak username
  validity)

---

## 5. SaaS Footprint Inference

By the time you've parsed SPF, DKIM, DMARC, and key DNS verification TXT
records, much of the SaaS footprint is already mapped. Fill in remaining
gaps with:

### CNAME chasing

Common SaaS apps live at predictable subdomain patterns:

- `support.example.com` → CNAME to Zendesk, Salesforce Service Cloud,
  Freshdesk, Intercom
- `careers.example.com` / `jobs.example.com` → Workday, Greenhouse, Lever,
  iCIMS, Taleo, SmartRecruiters
- `learn.example.com` / `lms.example.com` → Cornerstone, Workday Learning,
  Docebo, LinkedIn Learning
- `expense.example.com` / `concur.example.com` → SAP Concur
- `wiki.example.com` / `confluence.example.com` → Atlassian
- `chat.example.com` → Slack, Teams (rarer publicly), Mattermost
- `files.example.com` → Box, Dropbox, ShareFile
- `crm.example.com` → Salesforce, HubSpot, Microsoft Dynamics
- `hr.example.com` → Workday, BambooHR, Rippling, Gusto
- `pay.example.com` → ADP, Paylocity, Paycom

### Vendor case studies

Vendors love publishing customer success stories. Search:

- `"<Company>" site:vendorsite.com` for major SaaS vendors
- `"<Company> chose" OR "<Company> selected" OR "<Company> partners with"`
- Vendor "customers" pages — many list logos publicly

---

## 6. Endpoint and EDR Inference

EDR vendor identification is operationally critical for execution-phase
planning. Sources:

- **Job postings** — security engineering, SOC, and incident response
  postings list required experience with the deployed EDR. A posting
  asking for "3+ years CrowdStrike Falcon administration" is definitive.
- **LinkedIn skills and certifications** — `CrowdStrike Certified Falcon
  Administrator`, `SentinelOne Certified Engineer`, `Microsoft Defender
  for Endpoint Engineer` on staff profiles.
- **Press releases** — "Vendor X protects 50,000 endpoints at Company Y"
  announcements.
- **Public conference talks** — defender talks frequently disclose tool
  vendor.
- **Github repositories** — internal tooling forks, scripts referencing
  EDR APIs (`falcon_api.py`, `s1_helper.sh`).

The same approach works for SIEM (Splunk vs Sentinel vs Elastic vs
Chronicle vs LogRhythm vs QRadar) and for ITSM (ServiceNow vs Jira
Service Management vs Cherwell vs Ivanti).

---

## 7. Cloud Footprint Discovery

### AWS

- **Public S3 buckets** — search Grayhat Warfare, BuckHacker (when
  available), or `<company>` patterns: `<company>-prod`, `<company>-dev`,
  `<company>-backup`, `<company>-logs`, etc.
- **AWS account ID enumeration** from public S3 buckets — when you find
  a public bucket, request its ACL; the canonical user ID maps to the
  AWS account.
- **AWS-issued certificates** in CT logs reveal AWS-hosted services.
- **Public AMI sharing** — rare but possible, especially in research/
  bio companies.

### Azure / Microsoft 365

- **Tenant ID lookup** via the OpenID configuration endpoint
  (`/.well-known/openid-configuration`)
- **Azure DevOps / GitHub Enterprise on Azure** — `dev.azure.com/<org>`
  visibility checks for public projects
- **Public Storage accounts** — `<company>.blob.core.windows.net` may
  resolve and have public containers; check passively via DNS resolution
  alone, do not enumerate containers without authorization
- **Microsoft 365 tenant enumeration** via `getuserrealm.srf` (covered
  in section 4)

### GCP

- **Public Cloud Storage buckets** — `storage.googleapis.com/<company>-*`
  patterns
- **GCP project IDs** sometimes leak in public storage URLs and in
  open-source code commits

In all cases: passively observe what is publicly visible, do not probe.

---

## 8. GitHub and Public Code Reconnaissance

### Organizational discovery

- **GitHub org by name** — `github.com/<company>` is the obvious starting
  point. Many companies also have a parallel "labs" or "engineering" org.
- **Employee-attributed repos** — engineers' personal GitHub profiles
  often link to or fork from internal projects.
- **Forks of public projects** — organizations sometimes fork OSS
  projects publicly with internal modifications committed.

### Code search

GitHub's public code search (and the `gh search code` CLI) supports:

- `"company.com" in:file` — all references to the company's domain in
  any public code
- `org:<company>` filter — restrict to repos owned by the org
- Specific filename hits: `filename:.env`, `filename:config.yml`,
  `filename:docker-compose.yml`
- Language filter: `language:terraform "<company>"` for infrastructure
  references

### Secret detection

Once you have a candidate repo set, run **TruffleHog** (or comparable)
against the public repos to surface high-confidence secret matches.
TruffleHog is non-invasive — it operates on Git history, which is
public. Other tools: GitGuardian, gitleaks, Yelp's detect-secrets.

Common high-value finds:

- AWS access keys (and the corresponding account IDs)
- Slack tokens, GitHub PATs, npm tokens
- Database connection strings revealing internal hostnames
- API keys for Sentry, Datadog, New Relic, Twilio, SendGrid
- Internal hostnames in `Dockerfile`, `docker-compose.yml`,
  `terraform.tfvars`, `.env.example`
- Source code that references internal CI/CD URLs, internal package
  registries, internal artifact stores

### Recording

```json
{
  "repository": "github.com/<org>/<repo>",
  "visibility": "public",
  "interest": "AWS access key in commit abc123",
  "severity": "high",
  "remediation_status": "unverified",
  "source_ids": ["src-040"]
}
```

For any active credential, the engagement contract typically requires
prompt notification to the client even before the formal report — these
are typically not "save for the readout" findings.

---

## 9. Web Technology Fingerprinting

Passive web stack fingerprinting (you visit a public page in a browser,
which is what any user does) reveals:

- **Framework** — React/Next.js/Vue/Angular/Svelte from script tags and
  build artifact patterns
- **CMS** — WordPress, Drupal, Joomla, Sitecore, Adobe Experience Manager
  from URL patterns and meta tags
- **CDN/WAF** — from response headers (`server`, `via`, `x-served-by`,
  `cf-ray` for Cloudflare, `akamai-x-cache` for Akamai) and from CNAME
  resolution (Akamai, Cloudflare, Fastly, CloudFront, Azure Front Door)
- **Analytics** — Google Analytics, Adobe Analytics, Heap, Mixpanel,
  Segment, FullStory (each leaks a tag/account ID that can be pivoted)
- **Tag managers** — Google Tag Manager container IDs link sister
  properties owned by the same organization
- **Marketing automation** — Marketo, Pardot, HubSpot, Eloqua, Customer.io
  via tracking pixels and form actions
- **Live chat / support** — Drift, Intercom, Zendesk Chat, Olark,
  LiveChat, Crisp from script tags

Tooling: **BuiltWith** (free queries available), **Wappalyzer** (browser
extension or the public lookup), **WhatRuns**, **HTTP Archive** for
historical data on a target domain. All operate on public web data.

---

## 10. Job Postings as a Tech Disclosure Source

Job postings are the single richest legal source of internal tech stack
information. They directly disclose:

- Specific tools (by name, often with version)
- Cloud providers and accounts
- Programming languages and frameworks
- Internal team structure (who reports to whom)
- Recent initiatives ("Help us migrate from X to Y")
- Compliance regime (PCI, HIPAA, FedRAMP, SOX, GDPR mentions)
- Geographic footprint (office-based postings reveal where teams sit)

Where to look:

- Company careers page (the most current source)
- LinkedIn jobs (sometimes preserves postings the careers page has rotated)
- Indeed, Glassdoor (sometimes preserves expired postings)
- Wayback Machine snapshots of the careers page (recovers postings since
  removed — particularly useful when a posting was removed because the
  hire was made and the role's existence is operationally interesting)
- Niche boards: Stack Overflow Jobs (historical), AngelList/Wellfound for
  startups, BuiltIn for ecosystem-specific listings, GitHub Jobs (historical)

Mining technique:

1. Pull every posting (current + Wayback historical) for the target.
2. Extract every named tool, vendor, framework, and certification.
3. Aggregate: a tool named in 5 postings is operational; a tool named in
   1 posting is aspirational or experimental.
4. Cross-reference against staff profile skills (section 3 of
   people-intel.md) to triangulate confidence.

---

## Output Integration

Tech-stack collection feeds into the `tech_stack` block of
`target_profile.json`:

```json
"tech_stack": {
  "domains_and_subdomains": [/* schema in section 1 */],
  "edge": {"cdn": "Akamai", "waf": "Akamai Kona", "dns": "Akamai Edge DNS"},
  "email": {"mx": "outlook.com", "spf": "...", "dmarc": "...", "dkim_observed": [...]},
  "identity": {"idp": "Okta", "mfa": "Okta Verify + WebAuthn", "federation": [...]},
  "saas": [
    {"vendor": "Workday", "evidence": "SPF include + careers.example.com CNAME", "confidence": "confirmed", "source_ids": ["src-012"]}
  ],
  "endpoint_and_edr": [
    {"vendor": "CrowdStrike Falcon", "evidence": "Job posting + 4 staff certifications", "confidence": "high", "source_ids": ["src-019", "src-024"]}
  ],
  "cloud": {"aws": [{"account_id": null, "evidence": "Public S3 bucket + ACM certs"}], "azure": [...], "gcp": []},
  "code_repositories": [/* GitHub findings */]
}
```
