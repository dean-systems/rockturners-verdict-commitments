#!/usr/bin/env python3
"""Copies newly published verdict commitments into commitments/.

Reads COMMITMENTS_API (for example https://app.rockturners.com/api/public/commitments)
and LOOKBACK_DAYS (default 3), asks for every UTC date in that window, and writes each
commitment to commitments/YYYY/MM/<committed_at>.json. A file is written once and never
rewritten: if the server ever returns different content for a commitment already copied
here, this script fails, because a published commitment must never change.

Prints the path of each new file as soon as it is written. Any failure exits non-zero.
"""
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

FIELDS = {"algorithm", "claim_at", "committed_at", "completed_at", "date", "leaf_count", "root_hex", "scope"}
ALGORITHMS = {"sha256-merkle-v1"}
INSTANT = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?Z")
USER_AGENT = "rockturners-verdict-commitments/1 (+https://github.com/dean-systems/rockturners-verdict-commitments)"
ROOT = Path(__file__).resolve().parent.parent / "commitments"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def check(commitment):
    if set(commitment) != FIELDS:
        raise SystemExit(f"unexpected fields: {sorted(commitment)}")
    if commitment["algorithm"] not in ALGORITHMS:
        raise SystemExit(f"unknown algorithm: {commitment['algorithm']}")
    if not re.fullmatch(r"[0-9a-f]{64}", commitment["root_hex"]):
        raise SystemExit(f"malformed root: {commitment['root_hex']}")
    if not isinstance(commitment["leaf_count"], int) or commitment["leaf_count"] < 0:
        raise SystemExit(f"malformed leaf count: {commitment['leaf_count']}")
    for field in ("claim_at", "completed_at", "committed_at"):
        if not isinstance(commitment[field], str) or not INSTANT.fullmatch(commitment[field]):
            raise SystemExit(f"malformed {field}: {commitment[field]!r}")


def path_for(commitment):
    # committed_at was validated by check(); keep the full fraction so two commitments
    # made in the same second never share a file.
    year, month, day, hour, minute, second, fraction = INSTANT.fullmatch(commitment["committed_at"]).groups()
    stamp = f"{year}{month}{day}T{hour}{minute}{second}" + (f".{fraction}" if fraction else "") + "Z"
    target = (ROOT / year / month / f"{stamp}.json").resolve()
    if ROOT.resolve() not in target.parents:
        raise SystemExit(f"refusing to write outside commitments/: {target}")
    return target


def main():
    base = os.environ["COMMITMENTS_API"].rstrip("/")
    lookback = int(os.environ.get("LOOKBACK_DAYS", "3"))
    today = dt.datetime.now(dt.timezone.utc).date()
    ROOT.mkdir(parents=True, exist_ok=True)
    for offset in range(lookback, -1, -1):
        day = (today - dt.timedelta(days=offset)).isoformat()
        body = fetch(f"{base}/{day}")
        if body is None:
            continue
        for commitment in body["commitments"]:
            check(commitment)
            text = json.dumps(commitment, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            target = path_for(commitment)
            if target.exists():
                if target.read_text(encoding="utf-8") != text:
                    raise SystemExit(f"{target} was published before with different content")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            print(target.relative_to(ROOT.parent.resolve()).as_posix(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
