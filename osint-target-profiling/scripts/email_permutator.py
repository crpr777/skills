#!/usr/bin/env python3
"""
email_permutator.py — Generate likely email addresses from a name list and
target domain, according to common corporate email formats.

Reads a list of names (one per line, "First Last" or "First Middle Last") and
emits JSON in the schema shape used by target_profile.json's
contact_surface.harvested_emails array.

Usage:
    python email_permutator.py --domain example.com --names names.txt
    python email_permutator.py --domain example.com --names names.txt \\
        --formats first.last firstlast flast \\
        --confidence high \\
        --output emails.json

The default format set covers the most common North American corporate
patterns. Pass --formats to constrain to confirmed format(s) only.

Supported format tokens:
    first.last          jane.smith@example.com
    last.first          smith.jane@example.com
    firstlast           janesmith@example.com
    lastfirst           smithjane@example.com
    flast               jsmith@example.com
    firstl              janes@example.com
    f.last              j.smith@example.com
    first_last          jane_smith@example.com
    first-last          jane-smith@example.com
    first.middle.last   jane.q.smith@example.com (only if middle name given)
    first               jane@example.com
"""

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path


SUPPORTED_FORMATS = [
    "first.last",
    "last.first",
    "firstlast",
    "lastfirst",
    "flast",
    "firstl",
    "f.last",
    "first_last",
    "first-last",
    "first.middle.last",
    "first",
]

DEFAULT_FORMATS = ["first.last", "firstlast", "flast"]


def normalize(s: str) -> str:
    """Strip diacritics, lowercase, remove non-letter characters."""
    nfkd = unicodedata.normalize("NFKD", s)
    ascii_only = "".join(c for c in nfkd if not unicodedata.combining(c))
    ascii_only = ascii_only.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-zA-Z]", "", ascii_only).lower()


def parse_name(line: str):
    """Parse 'First Last' or 'First Middle Last' (or longer) into parts."""
    parts = [p for p in re.split(r"\s+", line.strip()) if p]
    if len(parts) < 2:
        return None
    first = normalize(parts[0])
    last = normalize(parts[-1])
    middle = normalize(parts[1]) if len(parts) >= 3 else ""
    if not first or not last:
        return None
    return {
        "raw": line.strip(),
        "first": first,
        "middle": middle,
        "last": last,
    }


def apply_format(fmt: str, name: dict) -> str | None:
    f = name["first"]
    m = name["middle"]
    l = name["last"]
    fi = f[0] if f else ""
    mi = m[0] if m else ""
    li = l[0] if l else ""
    if fmt == "first.last":
        return f"{f}.{l}"
    if fmt == "last.first":
        return f"{l}.{f}"
    if fmt == "firstlast":
        return f"{f}{l}"
    if fmt == "lastfirst":
        return f"{l}{f}"
    if fmt == "flast":
        return f"{fi}{l}"
    if fmt == "firstl":
        return f"{f}{li}"
    if fmt == "f.last":
        return f"{fi}.{l}"
    if fmt == "first_last":
        return f"{f}_{l}"
    if fmt == "first-last":
        return f"{f}-{l}"
    if fmt == "first.middle.last":
        if not m:
            return None
        return f"{f}.{m}.{l}"
    if fmt == "first":
        return f
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domain", help="Target email domain (e.g. example.com)")
    ap.add_argument("--names", type=Path, help="Path to text file with one name per line")
    ap.add_argument("--formats", nargs="+", default=DEFAULT_FORMATS, choices=SUPPORTED_FORMATS,
                    help=f"Format tokens to apply. Default: {' '.join(DEFAULT_FORMATS)}")
    ap.add_argument("--confidence", default="medium",
                    choices=["confirmed", "high", "medium", "low"],
                    help="Confidence rating to apply to all generated entries (default: medium)")
    ap.add_argument("--output", "-o", type=Path, help="Output JSON file. Default: stdout")
    ap.add_argument("--list-formats", action="store_true", help="List supported formats and exit")
    args = ap.parse_args()

    if args.list_formats:
        for f in SUPPORTED_FORMATS:
            print(f)
        return

    if not args.domain or not args.names:
        ap.error("--domain and --names are required (unless --list-formats)")
    if not args.names.exists():
        sys.exit(f"name file not found: {args.names}")

    names = []
    for line in args.names.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parsed = parse_name(line)
        if parsed:
            names.append(parsed)

    seen = set()
    entries = []
    for name in names:
        for fmt in args.formats:
            local = apply_format(fmt, name)
            if not local:
                continue
            email = f"{local}@{args.domain.lower()}"
            if email in seen:
                continue
            seen.add(email)
            entries.append({
                "email": email,
                "person_id": None,
                "name": name["raw"],
                "title": None,
                "format_confidence": args.confidence,
                "is_high_value_target": False,
                "tags": [f"format:{fmt}"],
                "source_ids": [],
            })

    out = json.dumps(entries, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(out + "\n", encoding="utf-8")
        print(f"wrote {len(entries)} entries to {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
