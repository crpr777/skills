#!/usr/bin/env python3
"""
linkedin_role_parser.py — Parse a pasted LinkedIn-style roster (one person
per row, tab- or pipe-separated: name, title, optional location, optional
"started X months ago" tenure indicator) and classify each entry into the
target_profile.json categories: executives, it_and_security_staff,
recent_hires, recent_departures.

This is a heuristic classifier, not a substitute for human judgment. It
exists to do the boring 80% so the operator can spend time on the 20%
that needs context.

Usage:
    python linkedin_role_parser.py --input roster.tsv --output people.json
    cat roster.tsv | python linkedin_role_parser.py --output people.json

Input format (one entry per line, tab-separated):
    Jane Smith<TAB>VP Engineering<TAB>Seattle, WA<TAB>3 years
    Bob Lee<TAB>Helpdesk Technician<TAB>Plano, TX<TAB>2 months
    Alice Wong<TAB>CISO<TAB>San Francisco, CA<TAB>5 years

The fourth field is optional and is parsed as tenure. Anything matching
"X months" with X <= 3 is marked as a recent_hire candidate.

Pipe-separated input is also accepted.

Output is written as JSON in the people block schema, with each entry's
target classification and the matching keywords for auditability.
"""

import argparse
import json
import re
import sys
from pathlib import Path


EXECUTIVE_TITLES = [
    r"\bchief\b",
    r"\bcxo\b",
    r"\bceo\b",
    r"\bcfo\b",
    r"\bcoo\b",
    r"\bcio\b",
    r"\bciso\b",
    r"\bcto\b",
    r"\bchro\b",
    r"\bcmo\b",
    r"\bcro\b",
    r"\bcdo\b",
    r"\bgeneral counsel\b",
    r"\bpresident\b",
    r"\bfounder\b",
    r"\bco[-\s]?founder\b",
    r"\bevp\b",
    r"\bsvp\b",
    r"\bvp\b",
    r"\bvice president\b",
    r"\bexecutive vice president\b",
    r"\bsenior vice president\b",
    r"\bmanaging director\b",
    r"\bhead of\b",
    r"\bdirector\b",
]

IT_SECURITY_TITLES = [
    r"\bhelp\s?desk\b",
    r"\bservice\s?desk\b",
    r"\bit support\b",
    r"\bdesktop support\b",
    r"\bsystem(s)? administrator\b",
    r"\bsysadmin\b",
    r"\bnetwork engineer\b",
    r"\bnetwork operations\b",
    r"\bnetops\b",
    r"\bsoc analyst\b",
    r"\bsecurity analyst\b",
    r"\bdetection engineer\b",
    r"\bsecurity engineer\b",
    r"\binformation security\b",
    r"\binfosec\b",
    r"\bcyber security\b",
    r"\bcybersecurity\b",
    r"\bidentity (and|&) access\b",
    r"\biam engineer\b",
    r"\bcloud (engineer|architect)\b",
    r"\bdevops\b",
    r"\bsre\b",
    r"\bsite reliability\b",
    r"\bapplication security\b",
    r"\bappsec\b",
    r"\bproduct security\b",
    r"\bvulnerability management\b",
    r"\bgrc\b",
    r"\bcompliance\b",
    r"\bincident response\b",
    r"\bthreat (intel|hunt)\b",
    r"\bpenetration test\b",
    r"\bred team\b",
    r"\bblue team\b",
    r"\bpurple team\b",
    r"\bsecurity architect\b",
    r"\binfrastructure engineer\b",
    r"\bplatform engineer\b",
    r"\bwindows admin\b",
    r"\blinux admin\b",
    r"\bactive directory\b",
    r"\bazure ad\b",
    r"\bentra\b",
    r"\bokta\b",
    r"\bcrowdstrike\b",
    r"\bsplunk admin\b",
    r"\bsentinel engineer\b",
]

GATEKEEPER_TITLES = [
    r"\bexecutive assistant\b",
    r"\boffice manager\b",
    r"\breceptionist\b",
    r"\boffice administrator\b",
    r"\bchief of staff\b",
]

FINANCIAL_AUTHORITY_TITLES = [
    r"\baccounts payable\b",
    r"\baccounts receivable\b",
    r"\bcontroller\b",
    r"\btreasur(er|y)\b",
    r"\baccounting manager\b",
    r"\bfinance manager\b",
    r"\bfinance director\b",
]


def match_any(title: str, patterns) -> list[str]:
    matches = []
    for p in patterns:
        if re.search(p, title, re.IGNORECASE):
            matches.append(p)
    return matches


def parse_tenure_months(field: str | None):
    """Parse tenure descriptors like '2 months', '1 year', '3 years 4 months'."""
    if not field:
        return None
    m = re.search(r"(\d+)\s*(month|year|yr|mo)", field, re.IGNORECASE)
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2).lower()
    if unit.startswith("year") or unit == "yr":
        return n * 12
    return n


def split_row(row: str):
    if "\t" in row:
        return [f.strip() for f in row.split("\t")]
    if "|" in row:
        return [f.strip() for f in row.split("|")]
    return [row.strip()]


def classify_one(name: str, title: str, location: str, tenure_months: int | None):
    classifications = []
    matches = {}

    gate_hits = match_any(title, GATEKEEPER_TITLES)
    # If this is a gatekeeper role, do NOT also classify as executive even if
    # the title contains an exec keyword (e.g., "Executive Assistant to CEO"
    # contains "ceo" but Carol is not the CEO).
    if gate_hits:
        exec_hits = []
    else:
        exec_hits = match_any(title, EXECUTIVE_TITLES)
    it_hits = match_any(title, IT_SECURITY_TITLES)
    fin_hits = match_any(title, FINANCIAL_AUTHORITY_TITLES)

    if exec_hits:
        classifications.append("executives")
        matches["executive_keywords"] = exec_hits
    if it_hits:
        classifications.append("it_and_security_staff")
        matches["it_security_keywords"] = it_hits
    if tenure_months is not None and tenure_months <= 3:
        classifications.append("recent_hires")
        matches["tenure_months"] = tenure_months

    hvt_reasons = []
    if exec_hits:
        hvt_reasons.append("Executive role")
    if any("ciso" in m.lower() or "cio" in m.lower() or "cto" in m.lower()
           or "cfo" in m.lower() for m in exec_hits):
        hvt_reasons.append("C-suite tech or finance authority")
    if it_hits and tenure_months is not None and tenure_months <= 3:
        hvt_reasons.append("Recent hire into privileged role")
    if gate_hits:
        hvt_reasons.append("Gatekeeper role (high-trust phishing target)")
        matches["gatekeeper_keywords"] = gate_hits
    if fin_hits:
        hvt_reasons.append("Wire-transfer or invoice authority")
        matches["financial_keywords"] = fin_hits

    return {
        "name": name,
        "title": title,
        "location": location or None,
        "tenure_months": tenure_months,
        "classifications": classifications,
        "is_high_value_target": bool(hvt_reasons),
        "hvt_rationale": "; ".join(hvt_reasons) if hvt_reasons else None,
        "matched_keywords": matches,
        "source_ids": [],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", "-i", help="Input file. Default: stdin")
    ap.add_argument("--output", "-o", help="Output JSON file. Default: stdout")
    args = ap.parse_args()

    if args.input:
        text = Path(args.input).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    rows = [r for r in text.splitlines() if r.strip() and not r.lstrip().startswith("#")]

    by_bucket = {
        "executives": [],
        "it_and_security_staff": [],
        "recent_hires": [],
        "recent_departures": [],
        "high_value_targets": [],
        "uncategorized": [],
    }

    for row in rows:
        fields = split_row(row)
        if len(fields) < 2:
            continue
        name = fields[0]
        title = fields[1]
        location = fields[2] if len(fields) >= 3 else ""
        tenure_field = fields[3] if len(fields) >= 4 else None
        tenure_months = parse_tenure_months(tenure_field)

        entry = classify_one(name, title, location, tenure_months)

        if not entry["classifications"]:
            by_bucket["uncategorized"].append(entry)
        else:
            for bucket in entry["classifications"]:
                by_bucket[bucket].append(entry)
        if entry["is_high_value_target"]:
            by_bucket["high_value_targets"].append(entry)

    out = json.dumps(by_bucket, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
        total = sum(len(v) for v in by_bucket.values())
        summary = ", ".join(f"{k}={len(v)}" for k, v in by_bucket.items())
        print(f"wrote {total} classified entries to {args.output} ({summary})", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
