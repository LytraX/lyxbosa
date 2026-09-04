#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§7.2 - the gate that runs before any shard is built. Fails the build, never warns.

`publishable` is a COMPUTED field, not a human assertion (§4.4). This script is the only
thing allowed to compute it, so the rule lives in exactly one place.

The rule (§4.1): a sample is publishable when its verdict is not `unreviewed` AND every
sensitivity tag is `clean`, `c2`, or has been masked and re-verified. `pii` and `content`
are never publishable, because there is no substitution that makes them safe.
"""
import json, sys, collections

ALWAYS_OK = {"clean", "c2"}
NEVER = {"pii", "content"}

def evaluate(r):
    why = []
    if r.get("verdict") == "unreviewed":
        why.append("verdict is unreviewed: nothing leaves that state without a human")
    tags = set(r.get("sensitivity") or [])
    bad = tags & NEVER
    if bad:
        why.append("carries %s, which is not maskable and is never published"
                   % "/".join(sorted(bad)))
    if "unreviewed" in tags:
        why.append("sensitivity not yet assessed")
    if "undecidable" in tags:
        why.append("obfuscated and did not decode: held local-only permanently")
    unmasked = tags - ALWAYS_OK - NEVER - {"unreviewed", "undecidable"}
    m = r.get("masking") or {}
    if unmasked:
        if not m.get("applied"):
            why.append("carries %s but no masking has been applied" % "/".join(sorted(unmasked)))
        else:
            if m.get("plaintext_gate") != "PASS":
                why.append("plaintext gate did not pass")
            if m.get("encoded_layer_gate") != "PASS":
                why.append("encoded-layer gate did not pass")
            if not m.get("detection_survived"):
                why.append("masking changed the detection set")
    if r.get("local_only"):
        why.append("marked local_only: %s" % r["local_only"])
    return (not why), why

def main(path, apply_fix=False):
    rows = [json.loads(l) for l in open(path)]
    changed = 0
    viol = collections.Counter()
    examples = collections.defaultdict(list)
    for r in rows:
        ok, why = evaluate(r)
        if r.get("publishable") != ok:
            changed += 1
            if r.get("publishable") and not ok:
                for w in why:
                    viol[w] += 1
                    if len(examples[w]) < 2:
                        examples[w].append(r["sha256"][:12])
        if apply_fix:
            r["publishable"] = ok
            if ok:
                r.pop("publish_blocker", None)
                r.pop("publish_blockers", None)
            elif why:
                # Keep every reason. Storing only the first overwrites the specific,
                # actionable blocker ("identifier inside an encoded layer") with the generic
                # one ("verdict is unreviewed"), and the accounting then cannot see it.
                r["publish_blockers"] = why
                r["publish_blocker"] = why[0]
    print("rows                        :", len(rows))
    print("publishable flags corrected :", changed)
    print("now publishable             :", sum(1 for r in rows if evaluate(r)[0]))
    if viol:
        print()
        print("=== rows that claimed publishable but are not ===")
        for w, n in viol.most_common():
            print("  %-70s %5d  e.g. %s" % (w[:70], n, ", ".join(examples[w])))
    if apply_fix:
        with open(path, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
    return 1 if viol else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], "--fix" in sys.argv))
