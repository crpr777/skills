#!/usr/bin/env python3
"""
ct_query.py — Query crt.sh certificate transparency logs for a target domain
and emit unique subdomains in the schema shape used by target_profile.json's
tech_stack.domains_and_subdomains array.

Usage:
    python ct_query.py --domain example.com
    python ct_query.py --domain example.com --output subdomains.json
    python ct_query.py --domain example.com --include-wildcards --include-expired

Notes:
    - crt.sh is a public, free certificate transparency search service.
    - This is purely passive — we read from a public log database, not from
      target infrastructure.
    - For higher reliability over time, consider also running the same query
      against api.certspotter.com — sometimes one indexes entries the other
      hasn't yet.
"""

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone


CRTSH_URL = "https://crt.sh/?q={pattern}&output=json"


def fetch_crtsh(domain: str, timeout: int = 60):
    pattern = urllib.parse.quote(f"%.{domain}")
    url = CRTSH_URL.format(pattern=pattern)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "osint-target-profiling/ct_query (research)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    if not body.strip():
        return []
    return json.loads(body)


def hostnames_from_entry(entry):
    """A crt.sh entry's name_value field may contain multiple newline-separated SANs."""
    raw = entry.get("name_value", "")
    return [h.strip().lower() for h in raw.split("\n") if h.strip()]


INTERESTING_PATTERNS = [
    (r"\b(vpn|sslvpn|remote|access|gateway|gw)\b", "remote access endpoint"),
    (r"\b(mail|smtp|imap|owa|exchange|autodiscover)\b", "mail infrastructure"),
    (r"\b(dev|stage|staging|test|qa|uat|preprod)\b", "non-production environment"),
    (r"\b(admin|panel|portal|console|manage)\b", "administrative interface"),
    (r"\b(login|sso|auth|idp|federation|adfs)\b", "authentication endpoint"),
    (r"\b(jenkins|gitlab|jira|confluence|bitbucket|nexus|artifactory|sonar)\b", "developer tooling"),
    (r"\b(citrix|rdweb|rdp|wvd|avd)\b", "remote desktop"),
    (r"\b(api|graphql|rest)\b", "API endpoint"),
    (r"\b(monitor|grafana|kibana|splunk|prometheus|nagios|zabbix)\b", "monitoring infrastructure"),
    (r"\b(backup|bak|archive|legacy|old)\b", "legacy or backup system"),
    (r"\b(internal|intranet|corp|ad|directory|ldap)\b", "internal-facing infrastructure"),
    (r"\b(jump|bastion|jumphost)\b", "bastion host"),
    (r"\b(citrix|netscaler)\b", "Citrix infrastructure"),
    (r"\b(fileshare|ftp|sftp|webdav)\b", "file transfer endpoint"),
]


def classify(hostname: str):
    interesting = False
    reasons = []
    for pat, reason in INTERESTING_PATTERNS:
        if re.search(pat, hostname, re.IGNORECASE):
            interesting = True
            reasons.append(reason)
    return interesting, "; ".join(dict.fromkeys(reasons))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domain", required=True, help="Apex domain to query (e.g. example.com)")
    ap.add_argument("--output", "-o", help="Output JSON file. Default: stdout")
    ap.add_argument("--include-wildcards", action="store_true",
                    help="Include wildcard entries (*.example.com) in output")
    ap.add_argument("--timeout", type=int, default=60, help="Request timeout in seconds")
    ap.add_argument("--summary", action="store_true",
                    help="Print human-readable summary to stderr in addition to JSON output")
    args = ap.parse_args()

    try:
        raw = fetch_crtsh(args.domain, timeout=args.timeout)
    except Exception as exc:
        sys.exit(f"crt.sh query failed: {exc}")

    seen = {}
    for entry in raw:
        for hostname in hostnames_from_entry(entry):
            if not hostname:
                continue
            if hostname.startswith("*.") and not args.include_wildcards:
                continue
            if hostname.startswith("*."):
                hostname = hostname[2:]
                if hostname in seen:
                    seen[hostname]["wildcard_observed"] = True
                    continue
            if hostname in seen:
                continue
            interesting, reason = classify(hostname)
            seen[hostname] = {
                "hostname": hostname,
                "first_seen": entry.get("not_before"),
                "last_seen": entry.get("not_after"),
                "source": "crt.sh",
                "interesting": interesting,
                "interest_reason": reason or None,
                "wildcard_observed": False,
                "source_ids": [],
            }

    entries = sorted(seen.values(), key=lambda e: e["hostname"])
    out = json.dumps(entries, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"wrote {len(entries)} subdomain entries to {args.output}", file=sys.stderr)
    else:
        print(out)

    if args.summary:
        n_interesting = sum(1 for e in entries if e["interesting"])
        print(
            f"\n{len(entries)} unique hostnames ({n_interesting} flagged interesting) for {args.domain}",
            file=sys.stderr,
        )
        for e in entries:
            if e["interesting"]:
                print(f"  [*] {e['hostname']}  ({e['interest_reason']})", file=sys.stderr)


if __name__ == "__main__":
    main()
