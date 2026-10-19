# RockTurners verdict commitments

A public, timestamped record of the verdict commitments published by
[RockTurners](https://rockturners.com), a research platform that screens U.S.-listed
companies using their SEC EDGAR filings.

After each scheduled sweep of its built-in strategies, RockTurners computes one SHA-256
Merkle root over **every** result of that sweep and publishes it. This repository copies
each published root and timestamps it with [OpenTimestamps](https://opentimestamps.org),
which anchors it in the Bitcoin blockchain.

## What a commitment shows, and what it doesn't

- **It shows** that a specific, complete set of sweep results existed when the commitment
  was made, and that none of those results has been changed since. Changing any committed
  result changes the root.
- **It reveals nothing.** A root is a hash. It names no company, verdict, score or price.
- **It says nothing about whether any result was right**, and nothing in this repository
  is a statement about investment returns.

If a sweep is ever not committed (for example, during an outage), it shows here as a
missing file. A file that was published is never changed or removed.

RockTurners may later publish the results behind a commitment. Anyone can then recompute
the root from them and confirm it matches the one timestamped here, on the date it was
timestamped.

## What's in this repository

| Path | What it is |
|---|---|
| `commitments/YYYY/MM/<committed_at>.json` | One commitment, copied from the RockTurners API. Written once, never rewritten. |
| `commitments/YYYY/MM/<committed_at>.json.ots` | Its OpenTimestamps proof. |
| `reference/merkle.py` | A reference implementation of the algorithm (Python standard library only). |
| `test-vectors.json` | Known inputs and the hashes, roots and audit paths they produce. |
| `.github/workflows/publish.yml` | The job that copies and timestamps new commitments every six hours. |

A commitment file has these fields:

| Field | Meaning |
|---|---|
| `date` | The UTC date the commitment was made. |
| `algorithm` | `sha256-merkle-v1`, specified below. |
| `root_hex` | The Merkle root, lowercase hex. |
| `leaf_count` | How many results the root covers. A dropped result would change this. |
| `scope` | `strategy_ids` and `scan_ids` of the sweep, `ticker_count`, `scans_in_flight` (scans still running when the commitment was made; normally 0), `scans_stopped_by_watchdog` (scans the sweep stopped because they stalled, whose work may not have ended; normally 0), and `exclusions`. `"none"` means every result of the sweep's scans is included, including results with no verdict. `"rows_written_later_by_in_flight_scans"` means a scan could still write results after the commitment was made (it was still running after a six-hour wait, or the sweep stopped it), and any such results are not covered. |
| `claim_at`, `completed_at` | When the sweep started and finished. |
| `committed_at` | When the commitment was made. |

## The algorithm: `sha256-merkle-v1`

**1. One leaf per result.** A leaf is a JSON object with exactly these 13 fields:

| Field | Type |
|---|---|
| `analyzed_at` | UTC timestamp, millisecond precision: `2026-10-12T05:14:03.112Z` |
| `citation_section_ids` | array of the filing sections the result cited, sorted by UTF-16 code unit and de-duplicated, or `null` |
| `confidence` | string or `null` |
| `evidence_as_of` | date `YYYY-MM-DD` of the newest filing evidence, or `null` |
| `model_used` | string or `null` |
| `prompt_sha256` | lowercase hex SHA-256 of the instructions used, or `null` (the instructions themselves are never published) |
| `scan_id` | lowercase hyphenated UUID |
| `score_total` | integer or `null` |
| `strategy_id` | lowercase hyphenated UUID |
| `ticker` | string |
| `unknowns` | array of strings sorted by UTF-16 code unit (duplicates kept), or `null` |
| `verdict` | `STRONG_MATCH`, `PARTIAL_MATCH`, `NO_MATCH`, or `null` when no verdict was given |
| `verdict_capping_reason` | string or `null` |

**2. Canonical bytes.** The leaf is serialized with its keys sorted, no whitespace, and
strings escaped as in [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): only `"`, `\`
and U+0000 to U+001F are escaped (`\b \f \n \r \t`, otherwise `\u00xx` in lowercase hex);
every other character is written as UTF-8. Python's
`json.dumps(leaf, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` produces
exactly these bytes.

**3. Leaf hash.** `SHA-256(0x00 ‖ canonical bytes)`.

**4. Order.** Leaves are sorted by `scan_id`, then `ticker`, both compared by UTF-16 code unit. A commitment holds one leaf per (`scan_id`, `ticker`).

**5. Root.** The [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) Merkle Tree
Hash over the ordered leaf hashes: no leaves gives `SHA-256` of no bytes; one leaf gives
its leaf hash; for n > 1 leaves, split at the largest power of two below n and join the
two halves as `SHA-256(0x01 ‖ left ‖ right)`. The 0x00 and 0x01 prefixes keep a leaf from
being passed off as an interior node.

**6. Inclusion proofs.** One result can be checked against a root with its RFC 6962 audit
path, verified as in [RFC 9162 §2.1.3.2](https://www.rfc-editor.org/rfc/rfc9162#section-2.1.3.2).

## How to verify

- **The timestamp:** `ots verify commitments/2026/10/<file>.json.ots` (needs a Bitcoin
  node), or upload the `.json` and its `.ots` at <https://opentimestamps.org>.
- **The algorithm:** `python3 reference/merkle.py selftest` recomputes every value in
  `test-vectors.json`.
- **A revealed sweep:** save its leaves as a JSON array and run
  `python3 reference/merkle.py root leaves.json`; the output must equal the commitment's
  `root_hex` and `leaf_count`.
- **One revealed result:**
  `python3 reference/merkle.py verify leaf.json INDEX COUNT ROOT_HEX PROOF_HEX...`

## Not investment advice

RockTurners provides research and analysis for educational purposes only. Not investment
advice. Consult a licensed financial professional before making investment decisions.

RockTurners is a research platform and publisher, not an investment adviser. Nothing in
this repository is a recommendation about any security.

Published by RockTurners, LLC. This repository is maintained by Dean Systems
Enterprises, LLC.
