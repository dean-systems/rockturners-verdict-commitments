"""Regenerates test-vectors.json from the reference implementation. The same
values are pinned in RockTurners' VerdictCommitmentBuilderTests."""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "reference"))
import merkle  # noqa: E402

SCAN = "11111111-1111-1111-1111-111111111111"
STRAT = "22222222-2222-2222-2222-222222222222"


def leaf(ticker, **fields):
    base = {k: None for k in merkle.LEAF_FIELDS}
    base.update(scan_id=SCAN, strategy_id=STRAT, ticker=ticker)
    base.update(fields)
    return base


LEAVES = {
    "full": leaf("AAPL", analyzed_at="2026-10-12T05:14:03.112Z",
                 citation_section_ids=["item_1_business", "item_7_mda"], confidence="High",
                 evidence_as_of="2026-09-30", model_used="claude-sonnet-5",
                 prompt_sha256=hashlib.sha256("You are a test prompt.".encode()).hexdigest(),
                 score_total=82, unknowns=["a unknown", "b unknown"], verdict="STRONG_MATCH"),
    "suppressed": leaf("MSFT", analyzed_at="2026-10-12T05:20:00.000Z",
                       verdict_capping_reason="suppressed:all_sources_stub"),
    "escaping": leaf("BRK.B", analyzed_at="2026-10-12T06:00:00.500Z", citation_section_ids=[],
                     confidence="Low", evidence_as_of="2026-06-30", model_used="gpt-5.6",
                     prompt_sha256=hashlib.sha256("p".encode()).hexdigest(), score_total=0,
                     unknowns=["Item 1 — Business \"quoted\" back\\slash\nline\u0001ctl"],
                     verdict="NO_MATCH"),
    "simple_xom": leaf("XOM", analyzed_at="2026-10-12T07:00:00.000Z", verdict="PARTIAL_MATCH"),
    "simple_zzzz": leaf("ZZZZ", analyzed_at="2026-10-12T07:00:00.000Z", verdict="PARTIAL_MATCH"),
}


def main():
    out = {
        "algorithm": "sha256-merkle-v1",
        "leaves": [
            {"name": name, "leaf": l, "canonical_json": merkle.canonical(l), "leaf_hash": merkle.leaf_hash(l).hex()}
            for name, l in LEAVES.items()
        ],
        "roots": [],
        "inclusion_proofs": [],
    }
    for names in ([], ["full"], ["suppressed", "escaping", "full"], list(LEAVES)):
        out["roots"].append({"leaves": names, "root": merkle.root_of([LEAVES[n] for n in names]).hex()})
    for names, index in ((list(LEAVES), 4), (["full", "suppressed", "escaping"], 2), (list(LEAVES), 1)):
        hashes = [merkle.leaf_hash(l) for l in merkle.ordered([LEAVES[n] for n in names])]
        out["inclusion_proofs"].append({
            "leaves": names, "index": index,
            "proof": [p.hex() for p in merkle.audit_path(index, hashes)],
            "root": merkle.tree_hash(hashes).hex(),
        })
    target = Path(__file__).resolve().parent.parent / "test-vectors.json"
    target.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {target}")


if __name__ == "__main__":
    main()
