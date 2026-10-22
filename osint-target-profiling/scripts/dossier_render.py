#!/usr/bin/env python3
"""
dossier_render.py — Render a target_profile.json into the target_dossier.md
narrative deliverable per the structure specified in SKILL.md.

Usage:
    python dossier_render.py --input target_profile.json
    python dossier_render.py --input target_profile.json --output target_dossier.md

The renderer is deliberately conservative: it preserves operator-written
prose where present (executive_summary, narrative entry-point fields)
and only formats structured data into tables and lists. It does not
generate analysis or invent content.

If the input JSON is incomplete (still being built during collection),
the renderer skips empty sections rather than emitting placeholders.
"""

import argparse
import json
import sys
from pathlib import Path
from textwrap import indent


def h(level: int, text: str) -> str:
    return f"{'#' * level} {text}\n\n"


def fmt_kv_block(d: dict, fields: list[tuple[str, str]]) -> str:
    out = []
    for key, label in fields:
        val = d.get(key)
        if val in (None, "", [], {}):
            continue
        if isinstance(val, list):
            val = ", ".join(str(v) for v in val)
        out.append(f"- **{label}:** {val}")
    return "\n".join(out) + ("\n\n" if out else "")


def render_target(target: dict) -> str:
    if not target:
        return ""
    out = []
    name = target.get("primary_name", "Unknown Target")
    eng = target.get("engagement_id") or "n/a"
    collected = target.get("collected_at") or "n/a"
    operator = target.get("collected_by") or "n/a"
    out.append(f"# Target Profile: {name}\n")
    out.append(f"**Engagement:** {eng} | **Collected:** {collected} | **Operator:** {operator}\n\n")
    out.append(fmt_kv_block(target, [
        ("primary_domain", "Primary domain"),
        ("aliases", "Aliases / DBAs"),
        ("subsidiaries", "Subsidiaries"),
        ("headquarters", "Headquarters"),
        ("industry", "Industry"),
        ("employee_count_estimate", "Employee count (est.)"),
        ("revenue_estimate_usd", "Revenue (USD, est.)"),
    ]))
    return "".join(out)


def render_executive_summary(profile: dict) -> str:
    summary = profile.get("executive_summary")
    if not summary:
        return ""
    return h(2, "1. Executive Summary") + summary.strip() + "\n\n"


def render_corporate_footprint(cf: dict) -> str:
    if not cf:
        return ""
    out = [h(2, "2. Corporate Footprint")]
    locs = cf.get("locations") or []
    if locs:
        out.append("**Locations**\n\n")
        out.append("| Address | Function | Approx. Headcount |\n")
        out.append("|---|---|---|\n")
        for loc in locs:
            out.append(
                f"| {loc.get('address', '')} | {loc.get('function', '')} | "
                f"{loc.get('headcount', 'n/a')} |\n"
            )
        out.append("\n")

    leaders = cf.get("leadership_roster") or []
    if leaders:
        out.append("**Leadership Roster**\n\n")
        out.append("| Name | Title | Tenure | Prior Employers |\n")
        out.append("|---|---|---|---|\n")
        for L in leaders:
            prior = ", ".join(L.get("prior_employers", []) or []) or "—"
            out.append(
                f"| {L.get('name', '')} | {L.get('title', '')} | "
                f"{L.get('tenure_at_target', '—')} | {prior} |\n"
            )
        out.append("\n")

    rels = cf.get("named_relationships") or {}
    rel_lines = []
    for k, label in [("auditor", "Auditor"), ("outside_counsel", "Outside Counsel")]:
        v = rels.get(k)
        if v:
            rel_lines.append(f"- **{label}:** {v}")
    for k, label in [
        ("msp_or_mssp", "MSP / MSSP"),
        ("named_customers", "Named Customers"),
        ("named_vendors", "Named Vendors"),
    ]:
        items = rels.get(k) or []
        if items:
            rel_lines.append(f"- **{label}:** {', '.join(items)}")
    if rel_lines:
        out.append("**Named Third-Party Relationships**\n\n")
        out.append("\n".join(rel_lines) + "\n\n")

    events = cf.get("recent_events") or []
    if events:
        out.append("**Recent Corporate Events**\n\n")
        for ev in events:
            out.append(
                f"- {ev.get('date', '')}: {ev.get('summary', '')}\n"
            )
        out.append("\n")

    return "".join(out) if len(out) > 1 else ""


def render_people_table(label: str, people: list, columns: list[tuple[str, str]]) -> str:
    if not people:
        return ""
    out = [f"**{label}**\n\n"]
    out.append("| " + " | ".join(c[1] for c in columns) + " |\n")
    out.append("|" + "|".join(["---"] * len(columns)) + "|\n")
    for p in people:
        row = []
        for key, _ in columns:
            v = p.get(key, "")
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            row.append(str(v) if v not in (None, "") else "—")
        out.append("| " + " | ".join(row) + " |\n")
    out.append("\n")
    return "".join(out)


def render_people(people: dict) -> str:
    if not people:
        return ""
    out = [h(2, "3. People Intelligence")]
    out.append(render_people_table("Executive bench", people.get("executives") or [],
                                   [("name", "Name"), ("title", "Title"),
                                    ("tenure_at_target", "Tenure"),
                                    ("public_appearances", "Notable public footprint")]))
    out.append(render_people_table("IT and security staff", people.get("it_and_security_staff") or [],
                                   [("name", "Name"), ("title", "Title"),
                                    ("team", "Team / Function"),
                                    ("notable_skills", "Notable skills/certs")]))
    out.append(render_people_table("Recent hires (last 90 days)", people.get("recent_hires") or [],
                                   [("name", "Name"), ("title", "Title"),
                                    ("start_date", "Start"),
                                    ("prior_employer", "Prior employer")]))
    out.append(render_people_table("Recent departures", people.get("recent_departures") or [],
                                   [("name", "Name"), ("last_title", "Last title"),
                                    ("departure_date", "Departed"),
                                    ("departure_type", "Type")]))
    hvts = people.get("high_value_targets") or []
    if hvts:
        out.append("**High-Value Targets**\n\n")
        for h_ in hvts:
            out.append(
                f"- **{h_.get('name', '')}** — {h_.get('title', '')}. "
                f"_Rationale:_ {h_.get('rationale', h_.get('hvt_rationale', ''))}\n"
            )
        out.append("\n")
    return "".join(out) if len(out) > 1 else ""


def render_tech_stack(ts: dict) -> str:
    if not ts:
        return ""
    out = [h(2, "4. Technology Stack")]

    edge = ts.get("edge") or {}
    email = ts.get("email") or {}
    identity = ts.get("identity") or {}
    if any([edge, email, identity]):
        out.append("**Edge, Email, Identity**\n\n")
        rows = [
            ("CDN", edge.get("cdn")),
            ("WAF", edge.get("waf")),
            ("DNS", edge.get("dns")),
            ("MX", email.get("mx")),
            ("DMARC posture", email.get("dmarc")),
            ("Identity provider", identity.get("idp")),
            ("MFA", identity.get("mfa")),
        ]
        for k, v in rows:
            if v:
                out.append(f"- **{k}:** {v}\n")
        out.append("\n")

    saas = ts.get("saas") or []
    if saas:
        out.append("**Inferred SaaS footprint**\n\n")
        out.append("| Vendor | Confidence | Evidence |\n|---|---|---|\n")
        for s in saas:
            out.append(
                f"| {s.get('vendor', '')} | {s.get('confidence', '')} | "
                f"{s.get('evidence', '')} |\n"
            )
        out.append("\n")

    edr = ts.get("endpoint_and_edr") or []
    if edr:
        out.append("**Endpoint and EDR**\n\n")
        for e in edr:
            out.append(
                f"- {e.get('vendor', '')} ({e.get('confidence', '')}) — "
                f"{e.get('evidence', '')}\n"
            )
        out.append("\n")

    cloud = ts.get("cloud") or {}
    cloud_lines = []
    for provider in ["aws", "azure", "gcp"]:
        items = cloud.get(provider) or []
        if items:
            cloud_lines.append(f"- **{provider.upper()}:** "
                               + "; ".join(i.get("evidence", "") or
                                           i.get("account_id", "") or
                                           "(see JSON)" for i in items))
    if cloud_lines:
        out.append("**Cloud footprint**\n\n")
        out.append("\n".join(cloud_lines) + "\n\n")

    subdomains = ts.get("domains_and_subdomains") or []
    interesting = [s for s in subdomains if s.get("interesting")]
    if interesting:
        out.append(f"**Interesting subdomains** (full set in `target_profile.json`, "
                   f"{len(subdomains)} total)\n\n")
        out.append("| Hostname | Reason |\n|---|---|\n")
        for s in interesting:
            out.append(
                f"| `{s.get('hostname', '')}` | "
                f"{s.get('interest_reason', '')} |\n"
            )
        out.append("\n")

    repos = ts.get("code_repositories") or []
    if repos:
        out.append("**Public code repositories of interest**\n\n")
        for r in repos:
            sev = r.get("severity") or "info"
            out.append(
                f"- [{sev.upper()}] `{r.get('repository', '')}` — "
                f"{r.get('interest', '')}\n"
            )
        out.append("\n")

    return "".join(out) if len(out) > 1 else ""


def render_contact_surface(cs: dict) -> str:
    if not cs:
        return ""
    out = [h(2, "5. Contact Surface")]
    fmt = cs.get("email_format")
    if fmt:
        out.append(f"**Email format:** `{fmt}` "
                   f"(_confidence:_ {cs.get('email_format_confidence', 'n/a')})\n\n")
    emails = cs.get("harvested_emails") or []
    if emails:
        hvts = [e for e in emails if e.get("is_high_value_target")]
        out.append(
            f"**Harvested email list:** {len(emails)} total, "
            f"{len(hvts)} flagged high-value (full list in JSON)\n\n"
        )
        if hvts:
            out.append("| Email | Name | Title | Tags |\n|---|---|---|---|\n")
            for e in hvts[:25]:
                tags = ", ".join(e.get("tags", []) or [])
                out.append(
                    f"| `{e.get('email', '')}` | {e.get('name', '')} | "
                    f"{e.get('title', '')} | {tags} |\n"
                )
            if len(hvts) > 25:
                out.append(f"| _… {len(hvts) - 25} more in JSON …_ | | | |\n")
            out.append("\n")
    role_mb = cs.get("role_mailboxes") or []
    if role_mb:
        out.append("**Role-based mailboxes**\n\n")
        for r in role_mb:
            out.append(
                f"- `{r.get('address', '')}` — {r.get('function', '')}"
                + (f" _(operational value: {r.get('operational_value', '')})_"
                   if r.get('operational_value') else "")
                + "\n"
            )
        out.append("\n")
    phones = cs.get("phone_numbers") or []
    if phones:
        out.append("**Phone numbers**\n\n")
        for p in phones:
            label = p.get("type", "phone")
            assoc = p.get("associated_office") or p.get("associated_person_id") or ""
            out.append(
                f"- {p.get('number_e164', '')} ({label})"
                + (f" — {assoc}" if assoc else "") + "\n"
            )
        out.append("\n")
    return "".join(out) if len(out) > 1 else ""


def render_leakage(leak: dict) -> str:
    if not leak:
        return ""
    out = [h(2, "6. Data Leakage")]
    breaches = leak.get("breach_exposures") or []
    if breaches:
        out.append(f"**Breach exposures:** {len(breaches)} affected employees\n\n")
        out.append("| Email | Breaches | Data classes | Reuse likelihood |\n|---|---|---|---|\n")
        for b in breaches[:30]:
            br_names = ", ".join(x.get("breach_name", "") for x in b.get("breaches", []))
            classes = set()
            for x in b.get("breaches", []):
                for c in x.get("data_classes", []):
                    classes.add(c)
            out.append(
                f"| `{b.get('email', '')}` | {br_names} | "
                f"{', '.join(sorted(classes))} | {b.get('reuse_likelihood', '—')} |\n"
            )
        if len(breaches) > 30:
            out.append(f"| _… {len(breaches) - 30} more in JSON …_ | | | |\n")
        out.append("\n")

    secrets = leak.get("leaked_secrets") or []
    if secrets:
        out.append("**Leaked secrets in public code**\n\n")
        for s in secrets:
            sev = s.get("severity", "?")
            valid = s.get("validity_status", "?")
            note = " ⚠ client notification required" if s.get("client_notification_required") else ""
            out.append(
                f"- [{sev.upper()} / {valid}] {s.get('secret_type', '')} "
                f"in `{s.get('repository', '')}` — {s.get('operational_value', '')}{note}\n"
            )
        out.append("\n")

    docs = leak.get("indexed_documents") or []
    if docs:
        out.append("**Indexed sensitive documents**\n\n")
        for d in docs:
            out.append(
                f"- [{d.get('sensitivity', '?').upper()}] "
                f"`{d.get('url', '')}` — {d.get('rationale', '')}\n"
            )
        out.append("\n")
    return "".join(out) if len(out) > 1 else ""


def render_entry_points(eps: list) -> str:
    if not eps:
        return ""
    out = [h(2, "7. Ranked Entry Points")]
    for ep in sorted(eps, key=lambda e: e.get("rank", 999)):
        rank = ep.get("rank", "?")
        vector = ep.get("vector", "")
        techs = ep.get("attack_technique", []) or []
        tech_str = ", ".join(techs) if techs else "—"
        out.append(f"### {rank}. {vector}\n\n")
        out.append(f"**ATT&CK:** {tech_str}\n\n")
        if ep.get("narrative"):
            out.append(ep["narrative"].strip() + "\n\n")
        attrs = []
        for k, label in [
            ("plausibility", "Plausibility"),
            ("pretext_quality", "Pretext quality"),
            ("detection_risk", "Detection risk"),
            ("effort", "Effort"),
        ]:
            if ep.get(k):
                attrs.append(f"_{label}:_ {ep[k]}")
        if attrs:
            out.append(" | ".join(attrs) + "\n\n")
        sf = ep.get("supporting_findings") or []
        if sf:
            out.append("**Supporting findings:**\n")
            for s in sf:
                out.append(f"- {s}\n")
            out.append("\n")
    return "".join(out)


def render_sources(sources: list) -> str:
    if not sources:
        return ""
    out = [h(2, "8. Sources")]
    for i, s in enumerate(sources, start=1):
        sid = s.get("id", f"src-{i:03d}")
        url = s.get("url", "")
        retrieved = s.get("retrieved_at", "")
        notes = s.get("notes", "")
        out.append(f"{i}. `{sid}` — {url} _(retrieved {retrieved})_"
                   + (f" — {notes}" if notes else "") + "\n")
    out.append("\n")
    return "".join(out)


def render(profile: dict) -> str:
    parts = [
        render_target(profile.get("target") or {}),
        render_executive_summary(profile),
        render_corporate_footprint(profile.get("corporate_footprint") or {}),
        render_people(profile.get("people") or {}),
        render_tech_stack(profile.get("tech_stack") or {}),
        render_contact_surface(profile.get("contact_surface") or {}),
        render_leakage(profile.get("leakage") or {}),
        render_entry_points(profile.get("entry_points") or []),
        render_sources(profile.get("sources") or []),
    ]
    return "".join(p for p in parts if p)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", "-i", required=True, type=Path,
                    help="Input target_profile.json")
    ap.add_argument("--output", "-o", type=Path,
                    help="Output target_dossier.md. Default: stdout")
    args = ap.parse_args()

    if not args.input.exists():
        sys.exit(f"input file not found: {args.input}")
    profile = json.loads(args.input.read_text(encoding="utf-8"))

    md = render(profile)
    if args.output:
        args.output.write_text(md, encoding="utf-8")
        print(f"wrote {len(md)} bytes to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(md)


if __name__ == "__main__":
    main()
