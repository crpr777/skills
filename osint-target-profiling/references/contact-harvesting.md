# Contact Harvesting

Methodology for mapping the contact and communication surface of a target
organization. Covers email format inference and confirmation, role-based
mailbox discovery, phone tree mapping, and target-list construction for
phishing, vishing, and physical-pretext use.

All techniques in this file are passive. Do not actively probe the
target's mail server, do not send test emails to validate addresses, do
not call the target's switchboard to enumerate extensions during the
collection phase.

## Table of Contents

1. Email Format Inference
2. Email Format Confirmation
3. Building the Target Email List
4. Role-Based Mailboxes
5. Phone Numbers and Phone Tree
6. Mobile and SMS Surface
7. Social Media as a Contact Channel

---

## 1. Email Format Inference

The email address format is the single highest-leverage contact-surface
finding. With the format inferred and a name list from people-intel
collection, you produce a target list mechanically.

### Common formats

In rough order of frequency in corporate environments:

- `first.last@example.com` — most common in North American enterprises
- `firstlast@example.com` — common, especially in tech-sector mid-size
- `flast@example.com` — first initial + last name, common in finance
  and consulting
- `firstl@example.com` — rare but used in some firms
- `last.first@example.com` — common in continental European firms
- `first_last@example.com` — older convention, occasional
- `first.middle.last@example.com` — common when first.last collisions
  are frequent (large companies)
- `f.last@example.com` — first initial period last name
- `employeeID@example.com` — used by very large enterprises and some
  government / healthcare / education environments
- `first.last+suffix@example.com` — rare but seen at companies with
  multiple historical employees of the same name

### Sources of pre-confirmed format

These yield the format directly without inference:

- **Press releases and case studies** — typically include a media or
  investor-relations contact email at the bottom (`first.last@example.com`)
- **Conference talk slides** — speakers frequently include their email
  on the title slide
- **Public regulatory filings** — SEC filings sometimes include named
  contacts with email
- **Email signatures harvested from public mailing-list archives** —
  IETF working groups, OSS project mailing lists, public Bugzilla
  archives, public GitHub issue threads, ICANN proceedings
- **Whois records** before privacy was applied (historical lookups)
- **Bounce messages and DSNs** in publicly archived mailing lists
- **`mailto:` links on the company website**
- **Hunter.io / RocketReach / SignalHire / ContactOut** read-only views
  (free tiers reveal format and a sample even without account purchases)
- **Voter registration / FEC contributions / campaign disclosures**
  occasionally show employee email when given as the donor's contact

### Sources of inferred format

When no pre-confirmed format is available:

- **Multiple LinkedIn employee profiles** with custom email visible (rare
  but happens, especially for sales staff)
- **GitHub `git log` entries** for known employees in their public
  contributions to OSS projects (look for the company domain in the
  `From:` line — e.g., `Author: Jane Smith <jane.smith@example.com>`)
- **Public DNS reverse-lookup of mail headers** in archived public
  threads where employees emailed externally
- **Conference Q&A submission portals** (CFP) sometimes leak email when
  proposals are aggregated and indexed

### Disambiguation when multiple formats coexist

Large companies often have multiple formats from acquisitions, legacy
domains, and exception cases:

- Acquired-company employees may retain `first.last@acquired-co.com`
  even after the acquired-co.com mail flows to the parent's M365
- Executive aliases may differ from staff format (some companies use
  `j.smith@example.com` for execs but `jane.smith@example.com` for staff)
- Contractor and vendor accounts may use a `c-` or `v-` prefix
- Service accounts use a documented prefix (`svc-`, `sys-`)

When in doubt, record both candidate formats with confidence ratings and
choose the higher-volume format as the primary.

---

## 2. Email Format Confirmation

Once you have a candidate format, confirm it without sending mail to the
target.

### Validation sources

- **Hunter.io domain search** returns the format with a confidence score
  and example confirmed addresses
- **Manual cross-reference** — pick three known-confirmed addresses from
  press/conference/GitHub sources, verify each matches the candidate
  format. If all three match, the format is `confirmed`.
- **Microsoft Teams / Outlook person-card lookup** in some configurations
  reveals address formatting when an external party shares a meeting
  link, but this is usage-dependent and not reliable.

### What "confirmed" means

For the schema, use:

- `confirmed` — three or more independent confirmed addresses, all
  matching the same format
- `high` — one or two confirmed addresses matching, or vendor-asserted
  format from Hunter.io with high confidence score
- `medium` — inferred from a single signal
- `low` — guess based on industry norms only

---

## 3. Building the Target Email List

With names from people-intel and a confirmed format, generate the email
list mechanically.

### Generation rules

For each person in the target organization:

1. Apply the primary format to first/last name.
2. Strip diacritics and apply ASCII transliteration if the source name
   contains them (e.g., `José Pérez` → `jose.perez`).
3. Lowercase.
4. For first names that are nicknames (e.g., "Jenny" on LinkedIn vs.
   "Jennifer" in formal records), generate both variants when uncertain.
5. For hyphenated last names, generate both with and without the hyphen
   (some MTAs strip; some don't).
6. For employees with public middle initials, generate both with and
   without (e.g., `john.smith@`, `john.q.smith@`).

The bundled `scripts/email_permutator.py` automates this and outputs the
JSON schema shape directly.

### Schema

```json
{
  "email": "jane.smith@example.com",
  "person_id": "p-014",
  "name": "Jane Smith",
  "title": "VP Engineering",
  "format_confidence": "confirmed",
  "is_high_value_target": true,
  "tags": ["recent_hire", "privileged_role"],
  "source_ids": ["src-007", "src-019"]
}
```

### List hygiene

- **Deduplicate** by email address (after normalizing to lowercase).
- **Flag aliases** — many organizations route both `jane.smith@` and
  `jsmith@` to the same mailbox; record the primary and any known
  aliases under the same entry.
- **Mark non-targets** explicitly — board members, retirees still listed
  as advisors, and named individuals who are out of scope per the
  engagement contract should be marked `out_of_scope: true` rather than
  silently removed (so they don't get re-added in the next collection
  pass).
- **Note service accounts and shared mailboxes separately** — they
  belong in the `role_mailboxes` array, not `harvested_emails`.

---

## 4. Role-Based Mailboxes

Role-based mailboxes are operationally distinct from individual mailboxes
and are typically prime phishing recipients because they are:

- Read by multiple people (high probability of action)
- Often staffed by junior employees (less security training)
- Commonly used to receive unsolicited mail by job description (so a
  cold lure isn't suspicious)

### Common role mailboxes to enumerate

For each, check by published presence on the company website, in press
releases, and via Hunter.io:

**Customer-facing**

- `info@`, `contact@`, `hello@`, `support@`, `help@`, `service@`

**Administrative**

- `office@`, `admin@`, `reception@`, `operations@`

**Sales and partnerships**

- `sales@`, `partners@`, `bd@`, `business@`, `licensing@`

**HR and people**

- `hr@`, `recruiting@`, `careers@`, `jobs@`, `talent@`, `benefits@`,
  `payroll@`

**Finance**

- `ap@`, `ar@`, `billing@`, `invoices@`, `finance@`, `accounting@`,
  `treasury@`

**Legal and compliance**

- `legal@`, `compliance@`, `privacy@`, `dpo@`

**Security and IT**

- `security@`, `abuse@`, `noc@`, `it@`, `helpdesk@`, `servicedesk@`

**Press and investor relations**

- `press@`, `media@`, `pr@`, `comms@`, `ir@`, `investors@`

**Vendor and procurement**

- `vendors@`, `procurement@`, `purchasing@`, `supplier@`

### Verifying without sending mail

- **MX-side metadata** — some mail providers (notably Microsoft 365 with
  certain configurations) leak whether a mailbox exists via SMTP banner
  responses, but this is active probing and out of scope here.
- **Historic mention in archived correspondence** — public mailing list
  archives, regulatory complaint archives, government open-records
  responses, and court filings frequently reference role mailboxes as
  the addressee.
- **Privacy policy and terms-of-service documents** — these typically
  list one or more role mailboxes as the contact point.
- **Cookie consent banners and "Do Not Sell" links** — link to or
  display a `privacy@` mailbox.
- **Bug bounty / vulnerability disclosure pages** — list `security@` or
  similar.

### Schema

```json
{
  "address": "ap@example.com",
  "function": "accounts payable",
  "evidence_source_ids": ["src-008"],
  "operational_value": "Invoice-themed phishing pretext; target for vendor impersonation"
}
```

---

## 5. Phone Numbers and Phone Tree

Phone surface matters for vishing, smishing, and physical-pretext work.

### Sources

- **Company "contact us" page** (current) — main switchboard, regional
  office numbers, sometimes department lines
- **Wayback Machine snapshots of contact pages** — recover historical
  direct lines and extension lists since cleaned up
- **Press release contacts** — investor relations, media relations, and
  sometimes named-employee direct lines
- **SEC filings** — required to list a contact phone number for
  investor inquiries; 10-K and 10-Q list a corporate phone
- **LinkedIn** — many sales and BD people list direct dial in their
  contact info
- **Email signatures in archived public threads** — full sigs typically
  include direct dial
- **Conference attendee lists / sponsor materials** — when sponsoring,
  companies list a contact name and phone
- **Real estate / facilities filings** — building management directories
- **Yellow Pages / WhitePages aggregators** for the corporate switchboard

### Phone tree mapping

If a published main number ends in `-0000` or `-1000`, the company
likely uses a four-digit extension scheme aligned to the trunk. This is
useful in vishing because:

- Calling main switchboard and asking for "extension 1234" sounds
  legitimate even when extension 1234 doesn't exist
- Reciting an extension when impersonating an internal caller establishes
  legitimacy
- Some IVRs allow direct extension dialing without operator triage

Do not call to enumerate. Catalog the public-source extensions you have
already harvested and note the apparent numbering scheme.

### Schema

```json
{
  "number_e164": "+12025550123",
  "type": "main_switchboard | direct_dial | regional_office | toll_free",
  "associated_office": "HQ",
  "associated_person_id": null,
  "extension": null,
  "source_ids": ["src-005"]
}
```

---

## 6. Mobile and SMS Surface

When an engagement includes smishing or telephony-aware phishing
(MFA-fatigue, push-bombing pretext, "I'm calling from your bank"-style
lures), mobile numbers matter.

### Sources

- **LinkedIn Contact Info** for individuals who list mobile
- **Calendly / Cal.com / similar booking pages** linked from individual
  profiles often include a phone number
- **Conference proposal portals** (CFP) when speakers list contact info
- **Public-records-aggregator services** for executives whose home
  address and personal phones are listed (engagement contract typically
  governs whether use is in scope; default to *not* using personal
  contact info unless explicitly authorized)
- **Voicemail greeting harvesting** during the *execution* phase only,
  not collection — confirmed greetings are useful for impersonation
  (knowing what the legitimate VM sounds like) but only after
  authorization to call

For the collection phase: catalog public mobile numbers and the source.
Mark each entry with a `personal_use_authorized` boolean per engagement
scope.

---

## 7. Social Media as a Contact Channel

Beyond LinkedIn (covered in people-intel), other social platforms are
both contact channels and intelligence sources.

### Channels worth cataloging per executive and per corporate brand

- **X / Twitter** — active accounts, last-post date, follower/following
  ratio (signals of bot vs. real engagement), DM-open status
- **Mastodon** (technologically literate executives have begun migrating)
- **Bluesky** (similar)
- **GitHub** (treated as both code and identity surface)
- **Facebook** (corporate page; rarely individual for executives)
- **Instagram** (consumer-brand companies use it as customer support)
- **TikTok** (consumer-brand support)
- **Reddit** — corporate subreddits, AMA history, named-employee
  participation
- **Threads** (Meta) — same use pattern as X
- **YouTube** — corporate channel, executive-fronted videos (provide
  voice samples for vishing impersonation analysis under engagement scope)

### Operational value

- A platform where the company actively replies to customers is a
  plausible inbound contact channel for impersonation pretexts
- A platform where an executive personally posts is a plausible
  account-takeover target and a source of voice/style training for
  social engineering
- A platform where the company has been publicly criticized is a
  source of grievance pretext content

---

## Output Integration

Contact harvesting feeds into the `contact_surface` block of
`target_profile.json`:

```json
"contact_surface": {
  "email_format": "first.last@example.com",
  "email_format_confidence": "confirmed",
  "harvested_emails": [/* schema in section 3 */],
  "role_mailboxes": [/* schema in section 4 */],
  "phone_numbers": [/* schema in section 5 */]
}
```

The `harvested_emails` array is the deliverable that most directly
feeds the execution-phase phishing platform; produce it in clean
deduplicated form with confidence ratings on every entry.
