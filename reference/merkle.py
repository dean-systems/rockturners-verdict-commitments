#!/usr/bin/env python3
"""Reference implementation of the RockTurners verdict-commitment algorithm
"sha256-merkle-v1". Python standard library only.

    python3 reference/merkle.py selftest
        Recompute every value in test-vectors.json and check the input rules.

    python3 reference/merkle.py root LEAVES.json
        LEAVES.json is a JSON array of leaf objects. Prints the root and the
        leaf count to compare with a published commitment.

    python3 reference/merkle.py verify LEAF.json INDEX COUNT ROOT_HEX [PROOF_HEX ...]
        Checks one leaf against a published root with its audit path.

The algorithm:
  1. Leaf bytes: the leaf object as canonical JSON (keys sorted, no
     whitespace, UTF-8, only '"', '\\' and U+0000..U+001F escaped), as in
     RFC 8785 for the strings, integers and nulls a leaf contains.
     citation_section_ids is sorted and de-duplicated, unknowns is sorted
     (duplicates kept); both sorts compare UTF-16 code units.
  2. Leaf hash: SHA-256(0x00 || leaf bytes).
  3. Order: leaves sorted by scan_id, then ticker (UTF-16 code units). A
     commitment holds one leaf per (scan_id, ticker).
  4. Root: the RFC 6962 Merkle Tree Hash. No leaves: SHA-256 of nothing.
     One leaf: its leaf hash. n > 1: split at the largest power of two below
     n and join the halves as SHA-256(0x01 || left || right).
"""
import hashlib
import json
import sys
from pathlib import Path

LEAF_FIELDS = (
    "analyzed_at", "citation_section_ids", "confidence", "evidence_as_of",
    "model_used", "prompt_sha256", "scan_id", "score_total", "strategy_id",
    "ticker", "unknowns", "verdict", "verdict_capping_reason",
)


def utf16(text):
    """Sort key matching .NET's ordinal comparison (UTF-16 code units)."""
    return text.encode("utf-16-be")


def normalized(leaf):
    """The leaf with the README's array rules applied, as production hashes it."""
    if set(leaf) != set(LEAF_FIELDS):
        raise ValueError(f"a leaf has exactly these fields: {', '.join(LEAF_FIELDS)}")
    out = dict(leaf)
    if out["citation_section_ids"] is not None:
        out["citation_section_ids"] = sorted(set(out["citation_section_ids"]), key=utf16)
    if out["unknowns"] is not None:
        out["unknowns"] = sorted(out["unknowns"], key=utf16)
    return out


def canonical(leaf):
    return json.dumps(normalized(leaf), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(data):
    return hashlib.sha256(data).digest()


def leaf_hash(leaf):
    return sha256(b"\x00" + canonical(leaf).encode("utf-8"))


def node_hash(left, right):
    return sha256(b"\x01" + left + right)


def split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def tree_hash(hashes):
    n = len(hashes)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return hashes[0]
    k = split(n)
    return node_hash(tree_hash(hashes[:k]), tree_hash(hashes[k:]))


def audit_path(index, hashes):
    n = len(hashes)
    if n == 1:
        return []
    k = split(n)
    if index < k:
        return audit_path(index, hashes[:k]) + [tree_hash(hashes[k:])]
    return audit_path(index - k, hashes[k:]) + [tree_hash(hashes[:k])]


def ordered(leaves):
    result = sorted(leaves, key=lambda l: (utf16(l["scan_id"]), utf16(l["ticker"])))
    for a, b in zip(result, result[1:]):
        if a["scan_id"] == b["scan_id"] and a["ticker"] == b["ticker"]:
            raise ValueError(f"two leaves for scan {a['scan_id']} and ticker {a['ticker']}; a commitment holds one per pair")
    return result


def root_of(leaves):
    return tree_hash([leaf_hash(l) for l in ordered(leaves)])


def verify_inclusion(leaf_digest, index, count, proof, root):
    """RFC 9162 section 2.1.3.2."""
    if index < 0 or count <= 0 or index >= count:
        return False
    fn, sn, r = index, count - 1, leaf_digest
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def selftest(vectors_path):
    vectors = json.loads(Path(vectors_path).read_text(encoding="utf-8"))
    failures = []
    for case in vectors["leaves"]:
        if canonical(case["leaf"]) != case["canonical_json"]:
            failures.append(f"canonical json: {case['name']}")
        if leaf_hash(case["leaf"]).hex() != case["leaf_hash"]:
            failures.append(f"leaf hash: {case['name']}")
    by_name = {c["name"]: c["leaf"] for c in vectors["leaves"]}
    for case in vectors["roots"]:
        got = root_of([by_name[n] for n in case["leaves"]]).hex()
        if got != case["root"]:
            failures.append(f"root over {case['leaves']}: {got}")
    for case in vectors["inclusion_proofs"]:
        hashes = [leaf_hash(l) for l in ordered([by_name[n] for n in case["leaves"]])]
        path = [p.hex() for p in audit_path(case["index"], hashes)]
        if path != case["proof"]:
            failures.append(f"audit path {case['index']} of {case['leaves']}")
        if not verify_inclusion(hashes[case["index"]], case["index"], len(hashes),
                                [bytes.fromhex(p) for p in case["proof"]], bytes.fromhex(case["root"])):
            failures.append(f"verify {case['index']} of {case['leaves']}")

    # Input rules production enforces.
    full = by_name["full"]
    shuffled = dict(full, unknowns=list(reversed(full["unknowns"])),
                    citation_section_ids=list(reversed(full["citation_section_ids"])) + full["citation_section_ids"][:1])
    if leaf_hash(shuffled) != leaf_hash(full):
        failures.append("array order or a duplicate citation changed the leaf hash")
    try:
        ordered([full, dict(full)])
        failures.append("a duplicate (scan_id, ticker) was accepted")
    except ValueError:
        pass
    h0, h1 = leaf_hash(by_name["full"]), leaf_hash(by_name["escaping"])
    two_root = tree_hash([h0, h1])
    if verify_inclusion(h1, -1, 2, [h0], two_root) or verify_inclusion(h0, 0, 0, [], h0):
        failures.append("an index outside [0, count) verified")

    for failure in failures:
        print(f"FAIL {failure}")
    print("selftest passed" if not failures else f"selftest FAILED ({len(failures)})")
    return not failures


def main(argv):
    here = Path(__file__).resolve().parent
    if len(argv) >= 2 and argv[1] == "selftest":
        return 0 if selftest(argv[2] if len(argv) > 2 else here.parent / "test-vectors.json") else 1
    if len(argv) == 3 and argv[1] == "root":
        leaves = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        print(json.dumps({"root_hex": root_of(leaves).hex(), "leaf_count": len(leaves)}))
        return 0
    if len(argv) >= 6 and argv[1] == "verify":
        leaf = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        ok = verify_inclusion(leaf_hash(leaf), int(argv[3]), int(argv[4]),
                              [bytes.fromhex(p) for p in argv[6:]], bytes.fromhex(argv[5]))
        print("included" if ok else "NOT included")
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
