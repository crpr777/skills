#!/usr/bin/env python3
"""
attack_mapper.py — Map free-text entry-point descriptions to MITRE ATT&CK
techniques using a keyword-driven lookup. Used during Phase 6 (Synthesis)
of the OSINT collection workflow to consistently tag candidate entry
points with techniques and tactics.

Usage:
    echo "Spear-phishing recent hires with HR-themed lure" | python attack_mapper.py
    python attack_mapper.py --input entries.txt --output mapped.json
    python attack_mapper.py --describe T1566.001

The mapping table covers the techniques most commonly produced by OSINT
synthesis: initial-access, reconnaissance-derived, and resource-
development-adjacent. It is not exhaustive of all of ATT&CK; for
techniques outside the initial-access focus, consult attack.mitre.org
directly.

Output schema (one entry per input line):

    {
      "input": "...",
      "techniques": [
        {"id": "T1566.001", "name": "...", "tactic": "Initial Access",
         "matched_keywords": ["..."]}
      ]
    }
"""

import argparse
import json
import re
import sys
from pathlib import Path


TECHNIQUES = [
    # Reconnaissance (TA0043)
    {
        "id": "T1589", "name": "Gather Victim Identity Information",
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "keywords": ["employee email", "name list", "harvested email", "employee roster"],
    },
    {
        "id": "T1589.001", "name": "Gather Victim Identity Information: Credentials",
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "keywords": ["leaked password", "breach data", "haveibeenpwned", "dehashed",
                     "credential leak", "leaked credential"],
    },
    {
        "id": "T1589.002", "name": "Gather Victim Identity Information: Email Addresses",
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "keywords": ["email format", "email harvest", "hunter.io", "rocketreach"],
    },
    {
        "id": "T1591", "name": "Gather Victim Org Information",
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "keywords": ["org chart", "subsidiary", "leadership roster", "executive bench"],
    },
    {
        "id": "T1593", "name": "Search Open Websites/Domains",
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "keywords": ["linkedin", "github reconnaissance", "google dork",
                     "wayback machine", "shodan"],
    },
    {
        "id": "T1593.001", "name": "Search Open Websites/Domains: Social Media",
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "keywords": ["twitter", "x.com", "linkedin profile", "social media intel"],
    },
    {
        "id": "T1596.002", "name": "Search Open Technical Databases: WHOIS",
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "keywords": ["whois", "domain registration"],
    },
    {
        "id": "T1596.003", "name": "Search Open Technical Databases: Digital Certificates",
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "keywords": ["certificate transparency", "crt.sh", "ct log", "censys", "ssl cert"],
    },

    # Resource Development (TA0042)
    {
        "id": "T1583.001", "name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development", "tactic_id": "TA0042",
        "keywords": ["lookalike domain", "typosquat", "homoglyph",
                     "register domain", "phishing domain"],
    },
    {
        "id": "T1585.001", "name": "Establish Accounts: Social Media Accounts",
        "tactic": "Resource Development", "tactic_id": "TA0042",
        "keywords": ["fake linkedin", "sockpuppet", "fake persona", "fake recruiter"],
    },
    {
        "id": "T1585.002", "name": "Establish Accounts: Email Accounts",
        "tactic": "Resource Development", "tactic_id": "TA0042",
        "keywords": ["sender domain", "smtp infrastructure", "phishing sender"],
    },
    {
        "id": "T1586.002", "name": "Compromise Accounts: Email Accounts",
        "tactic": "Resource Development", "tactic_id": "TA0042",
        "keywords": ["compromised mailbox", "supplier email compromise",
                     "third-party email takeover"],
    },

    # Initial Access (TA0001)
    {
        "id": "T1078", "name": "Valid Accounts",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["valid credential", "reused password", "credential reuse",
                     "leaked credential", "stolen credential", "active credential"],
    },
    {
        "id": "T1078.004", "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["aws access key", "azure ad credential", "okta credential",
                     "cloud credential", "m365 credential", "entra credential"],
    },
    {
        "id": "T1133", "name": "External Remote Services",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["vpn", "rdp gateway", "citrix", "remote desktop gateway",
                     "rdweb", "ssl vpn", "rdp"],
    },
    {
        "id": "T1189", "name": "Drive-by Compromise",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["watering hole", "drive-by", "compromised website",
                     "browser exploit"],
    },
    {
        "id": "T1190", "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["public-facing", "web app exploit", "exposed admin",
                     "exposed jenkins", "exposed gitlab", "n-day exploit"],
    },
    {
        "id": "T1195", "name": "Supply Chain Compromise",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["supply chain", "third party", "vendor compromise",
                     "msp compromise", "mssp compromise"],
    },
    {
        "id": "T1199", "name": "Trusted Relationship",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["trusted relationship", "partner access", "vendor portal access"],
    },
    {
        "id": "T1566", "name": "Phishing",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["phishing", "phish", "social engineering email"],
    },
    {
        "id": "T1566.001", "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["spear-phishing attachment", "malicious attachment",
                     "weaponized document", "macro document", "iso payload"],
    },
    {
        "id": "T1566.002", "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["spear-phishing link", "phishing link", "credential harvest",
                     "fake login page", "evilginx", "aitm", "adversary in the middle"],
    },
    {
        "id": "T1566.003", "name": "Phishing: Spearphishing via Service",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["linkedin message", "teams message", "slack phish",
                     "platform phishing", "via service"],
    },
    {
        "id": "T1566.004", "name": "Phishing: Spearphishing Voice",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["vishing", "voice phishing", "phone-based social engineering",
                     "helpdesk impersonation", "callback phishing"],
    },
    {
        "id": "T1200", "name": "Hardware Additions",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["physical implant", "rogue device", "drop device",
                     "usb drop", "hardware add"],
    },
    {
        "id": "T1091", "name": "Replication Through Removable Media",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "keywords": ["usb drop", "removable media", "thumb drive"],
    },
    {
        "id": "T1621", "name": "Multi-Factor Authentication Request Generation",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "keywords": ["mfa fatigue", "push bombing", "mfa bombing", "push fatigue"],
    },
]


def find_techniques(text: str):
    matches = []
    lowered = text.lower()
    for tech in TECHNIQUES:
        matched_kws = [kw for kw in tech["keywords"] if kw.lower() in lowered]
        if matched_kws:
            matches.append({
                "id": tech["id"],
                "name": tech["name"],
                "tactic": tech["tactic"],
                "tactic_id": tech["tactic_id"],
                "matched_keywords": matched_kws,
            })
    return matches


def describe(technique_id: str):
    for t in TECHNIQUES:
        if t["id"].lower() == technique_id.lower():
            return {
                "id": t["id"],
                "name": t["name"],
                "tactic": t["tactic"],
                "tactic_id": t["tactic_id"],
                "trigger_keywords": t["keywords"],
            }
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", "-i", help="Input text file (one entry per line). Default: stdin")
    ap.add_argument("--output", "-o", help="Output JSON file. Default: stdout")
    ap.add_argument("--describe", help="Print details for a given technique ID and exit")
    ap.add_argument("--list", action="store_true", help="List all known techniques and exit")
    args = ap.parse_args()

    if args.list:
        for t in TECHNIQUES:
            print(f"{t['id']:12} {t['tactic']:25} {t['name']}")
        return

    if args.describe:
        info = describe(args.describe)
        if not info:
            sys.exit(f"unknown technique id: {args.describe}")
        print(json.dumps(info, indent=2))
        return

    if args.input:
        text = Path(args.input).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    results = []
    for ln in lines:
        results.append({"input": ln, "techniques": find_techniques(ln)})

    out = json.dumps(results, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
        unmatched = sum(1 for r in results if not r["techniques"])
        print(f"mapped {len(results) - unmatched}/{len(results)} entries; "
              f"{unmatched} produced no technique match", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
