#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Make `sensitivity` describe the decoded form of a sample, not just its wrapper.

WHAT WAS WRONG
--------------
A `deobfuscation` block records two tag sets: `encoded_form_tags` for the bytes as
collected, and `decoded_form_tags` for everything the static decoder got out of them. On 11
local rows the row's `sensitivity` equals `encoded_form_tags` while `decoded_form_tags` is
strictly larger, and `hidden_by_encoding` names the difference.

That is tagging a sample by the thing the encoder was for. §5.4's premise is that an
identifier inside an encoded layer makes a sample unpublishable - "the absence of a plaintext
hit is evidence the encoder worked, not evidence the sample is clean" - so a sensitivity read
off the wrapper is measuring the wrong object. Two of the eleven exposed it: both carry
credentials in a `base64+inflate` layer and both were tagged `clean`, one of them
`publishable: true` with zero blockers.

The ruling this implements: **sensitivity describes what the sample carries, including in
its decoded form.** So the decoded-form tags are adopted, and `clean` is dropped when
anything else is present - `sensitivity.py`'s own contract is that `clean` never appears
beside another tag.

WHAT THIS REFUSES
-----------------
  * **a row with no `decoded_form_tags`.** There is nothing to adopt. A `--fix` that
    computes the field it is about to trust is not a fix - it is the tool agreeing with
    itself, and §4.4's rule about never manufacturing a field applies with more force here
    because the field is an input to the publish gate.
  * **a row whose decoded tags are already covered.** Nothing to do, and rewriting the field
    anyway would put a change record on a row that did not change.
  * **writing `publishable`.** `shard-gate.py --fix` is the only thing allowed to compute it
    (§4.4), and this prints that as the next step.

WHAT IT IS NOT
--------------
It is not a re-derivation. `decoded_form_tags` is a claim recorded by an earlier pass, and
adopting it is trusting that pass; what this tool can assert is only that the row's own two
records disagree and which way. Whether the claim is *right* is a question for the bytes, and
the answer for these eleven is written up in SOURCES.md per row.

**And the population is bounded by that same pass.** `decoded_form_tags` exists on 142 of the
416 local rows that carry form tags at all; the other 274 are recorded `undecodable`, which
is a statement about one decoder rather than about the bytes. Re-running the *gate's* decoder
over the same 142 rows widens the decoded tags on 13 of them and narrows them on none, and
the under-covered count goes 11 -> 20. So 11 is what this comparison can see, not the size of
the population - §11's rule that a denominator enumerated by the process that produced the
numerator bounds the result and not reality. `--census` prints that arithmetic on every run,
because a numerator without it reads as a total.

    corpus/adopt-decoded-tags.py --index corpus/local/index-local.jsonl
    corpus/adopt-decoded-tags.py --index ... --by cl --apply
    corpus/adopt-decoded-tags.py --inject
"""
import argparse, copy, datetime, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy   # noqa: E402

# Written by this tool beside `sensitivity`, so a reader can see the tag moved and why.
RECORD_KEY = "sensitivity_adopted"
WRITABLE = ("sensitivity", RECORD_KEY)

WHY = ("sensitivity is taken from the sample's decoded form as well as its wrapper: the "
       "row's own deobfuscation record carried tags the sensitivity did not, and a tag read "
       "off the outer form of an obfuscated sample is a tag read off the thing the encoder "
       "was for")


def decoded_tags(row):
    """The recorded decoded-form tags, or None where the row has no such record.

    None and [] are different answers and are kept different: no record at all is a row this
    tool must not touch, and a recorded empty set is a pass that looked and found nothing.
    """
    d = row.get("deobfuscation")
    if not isinstance(d, dict) or "decoded_form_tags" not in d:
        return None
    v = d["decoded_form_tags"]
    return v if isinstance(v, list) else None


def proposal(row):
    """(new_sensitivity, added) or (None, reason). Exactly one form.

    `clean` is dropped whenever anything else survives, because `sensitivity.py` never
    returns it beside another tag and a gate reading `{"clean", "identity"}` would compute
    `unmasked` correctly and read as a contradiction to everyone else.
    """
    dt = decoded_tags(row)
    if dt is None:
        return None, "row records no decoded_form_tags; there is nothing to adopt"
    have = set(row.get("sensitivity") or [])
    add = set(dt) - have
    if not add:
        return None, "decoded_form_tags are already covered by sensitivity"
    merged = (have | set(dt)) - {"clean"}
    return sorted(merged) or ["clean"], sorted(add)


def build(row, by, at=None):
    """(after_row, refusal). Exactly one is None."""
    if not by or not by.strip():
        return None, "an author is required: an adopted tag has an owner like any other"
    new, added = proposal(row)
    if new is None:
        return None, added
    after = copy.deepcopy(row)
    after["sensitivity"] = new
    after[RECORD_KEY] = {
        "from": "deobfuscation.decoded_form_tags",
        "was": sorted(row.get("sensitivity") or []),
        "added": added,
        "by": by.strip(),
        "at": (at or datetime.datetime.now().replace(microsecond=0)).isoformat(),
        "why": WHY,
    }
    return after, None


def assert_additive(before, after):
    """None, or what changed that should not have.

    Both directions. The first version of the same assertion in `verify-and-stamp.py` could
    see an overwritten key and not an added one, and its own control caught it; this one is
    written from that.
    """
    moved = sorted({k for k in set(before) | set(after)
                    if before.get(k) != after.get(k)})
    extra = [k for k in moved if k not in WRITABLE]
    if extra:
        return "changed %s, which is outside %s" % ("/".join(extra), "/".join(WRITABLE))
    if "sensitivity" not in moved:
        return "sensitivity did not move, so nothing was adopted"
    if not set(before.get("sensitivity") or []) - {"clean"} <= set(after["sensitivity"]):
        return "an existing sensitivity tag was dropped"
    if "publishable" in moved:
        return "wrote publishable, which only shard-gate.py may compute"
    return None


def census(rows):
    """The denominator, printed on every run. Numerator without it reads as a total."""
    form = dec = under = 0
    for r in rows:
        d = r.get("deobfuscation")
        if not isinstance(d, dict):
            continue
        if "encoded_form_tags" in d:
            form += 1
        dt = decoded_tags(r)
        if dt is None:
            continue
        dec += 1
        if set(dt) - set(r.get("sensitivity") or []):
            under += 1
    return form, dec, under


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=os.path.join(HERE, "local", "index-local.jsonl"))
    ap.add_argument("--sha", action="append", default=[],
                    help="restrict to these rows, by sha256 prefix; repeatable")
    ap.add_argument("--by", default=None, help="who is adopting")
    ap.add_argument("--apply", action="store_true", help="write; default is a dry run")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()

    rows = read_jsonl(a.index)
    form, dec, under = census(rows)
    print("rows                              : %d" % len(rows))
    print("rows carrying encoded_form_tags   : %d" % form)
    print("rows carrying decoded_form_tags   : %d   <- the only rows this can compare" % dec)
    print("of those, decoded not covered     : %d" % under)
    print("the %d - %d rows with no decoded record are outside this comparison entirely; "
          "see the docstring" % (form, dec))
    print()

    def selected(r):
        if not a.sha:
            return True
        return any(r["sha256"].startswith(p) for p in a.sha)

    todo, skipped = [], []
    for r in rows:
        if not selected(r):
            continue
        new, added = proposal(r)
        if new is None:
            if a.sha:
                skipped.append((r["sha256"], added))
            continue
        todo.append((r["sha256"], sorted(r.get("sensitivity") or []), new, added))

    print("rows to adopt                     : %d" % len(todo))
    for sha, was, new, added in todo:
        print("  %s  %-32s -> %-46s  adds %s"
              % (sha[:12], was, new, added))
    for sha, why in skipped:
        print("  %s  skipped: %s" % (sha[:12], why))

    if not a.apply:
        print()
        print("dry run: nothing written. Re-run with --by <who> --apply.")
        return 0
    if not a.by:
        return ap.error("--by is required to write")

    want = {sha for sha, _w, _n, _a in todo}
    at = datetime.datetime.now().replace(microsecond=0)
    with index_lock(a.index):
        # Re-read inside the lock: the rows may have moved since the dry run, and a
        # sensitivity computed against a stale copy would adopt a tag set nobody recorded.
        rows = read_jsonl(a.index)
        n_before = len(rows)
        written = 0
        for i, r in enumerate(rows):
            if r["sha256"] not in want:
                continue
            after, refusal = build(r, a.by, at)
            if refusal:
                sys.exit("REFUSED on re-read under the lock: %s on %s"
                         % (refusal, r["sha256"][:12]))
            bad = assert_additive(r, after)
            if bad:
                sys.exit("refusing to write: %s on %s" % (bad, r["sha256"][:12]))
            rows[i] = after
            written += 1
        if len(rows) != n_before:
            sys.exit("row count moved %d -> %d" % (n_before, len(rows)))
        if written != len(want):
            sys.exit("expected to write %d row(s), wrote %d" % (len(want), written))
        write_jsonl_atomic(a.index, rows)
    print()
    print("rows written                      : %d" % written)
    print("`publishable` is NOT touched here - run")
    print("  corpus/shard-gate.py --fix %s" % os.path.relpath(a.index, os.getcwd()))
    print("which is the only thing allowed to compute it.")
    return 0


# ---------------------------------------------------------------------------------------
# Controls. One per refusal the design claims, plus the positive half for each: a tool that
# refuses everything adopts nothing and would pass a suite made only of refusals.
# ---------------------------------------------------------------------------------------

def inject():
    fails = []
    ran = []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-62s %-26s %s" % (label, str(got)[:26],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    def row(sens, dec=None, **kw):
        r = {"sha256": "0" * 64, "verdict": "malicious", "sensitivity": list(sens)}
        if dec is not None:
            r["deobfuscation"] = {"status": "decoded", "encoded_form_tags": list(sens),
                                  "decoded_form_tags": list(dec)}
        r.update(kw)
        return r

    print("=== it must REFUSE these ===")
    case("a row with no deobfuscation block at all",
         "refused" if build(row(["clean"]), "cl")[1] else "written", "refused")
    case("a row whose deobfuscation records no decoded_form_tags",
         "refused" if build({"sha256": "0" * 64, "sensitivity": ["clean"],
                             "deobfuscation": {"status": "undecodable",
                                               "encoded_form_tags": ["clean"]}}, "cl")[1]
         else "written", "refused")
    case("decoded_form_tags already covered",
         "refused" if build(row(["c2", "identity"], ["c2"]), "cl")[1] else "written",
         "refused")
    case("no author",
         "refused" if build(row(["clean"], ["identity"]), "  ")[1] else "written", "refused")
    # The field must never be computed here. A tool that can decode the bytes and write the
    # field it then trusts is agreeing with itself, and this is an input to the publish gate.
    case("decoded_form_tags is never manufactured",
         decoded_tags({"sha256": "0" * 64, "deobfuscation": {"status": "undecodable"}}),
         None)

    print()
    print("=== and ADOPT these ===")
    after, refusal = build(row(["clean"], ["identity", "secret"]), "cl")
    case("clean + decoded identity/secret", after["sensitivity"] if after else refusal,
         ["identity", "secret"])
    case("`clean` is dropped when anything else survives",
         "clean" not in (after["sensitivity"] if after else ["clean"]), True)
    case("the change records what it was",
         after[RECORD_KEY]["was"] if after else None, ["clean"])
    case("the change records what it added",
         after[RECORD_KEY]["added"] if after else None, ["identity", "secret"])
    case("the change records who and when",
         bool(after and after[RECORD_KEY]["by"] and after[RECORD_KEY]["at"]), True)
    a2, _ = build(row(["c2"], ["c2", "path"]), "cl")
    case("an existing tag is kept, not replaced", a2["sensitivity"], ["c2", "path"])
    a3, _ = build(row(["identity"], ["c2"]), "cl")
    case("a decoded tag in ALWAYS_OK is still adopted", a3["sensitivity"], ["c2", "identity"])
    a4, _ = build(row(["clean"], ["pii"]), "cl")
    case("pii is adopted like any other tag - NEVER is the gate's rule, not this one",
         a4["sensitivity"], ["pii"])

    print()
    print("=== the write must be additive and must not compute publishability ===")
    base = row(["clean"], ["identity"], publishable=True)
    after, _ = build(base, "cl")
    case("nothing outside sensitivity/%s moves" % RECORD_KEY,
         assert_additive(base, after) or "clean", "clean")
    tampered = copy.deepcopy(after)
    tampered["publishable"] = False
    case("writing publishable alongside is caught",
         "caught" if assert_additive(base, tampered) else "MISSED", "caught")
    tampered2 = copy.deepcopy(after)
    tampered2["verdict"] = "benign"
    case("a change outside the allow-list is caught",
         "caught" if assert_additive(base, tampered2) else "MISSED", "caught")
    dropped = copy.deepcopy(after)
    dropped["sensitivity"] = ["identity"]
    b2 = row(["c2"], ["identity"])
    a5, _ = build(b2, "cl")
    a5["sensitivity"] = ["identity"]          # c2 silently dropped
    case("dropping an existing tag is caught",
         "caught" if assert_additive(b2, a5) else "MISSED", "caught")
    same = copy.deepcopy(base)
    case("a row that did not move is caught",
         "caught" if assert_additive(base, same) else "MISSED", "caught")

    print()
    print("=== the census must state the denominator it can see ===")
    pop = [row(["clean"], ["identity"]),
           row(["c2"], ["c2"]),
           {"sha256": "1" * 64, "sensitivity": ["clean"],
            "deobfuscation": {"status": "undecodable", "encoded_form_tags": ["clean"]}},
           {"sha256": "2" * 64, "sensitivity": ["clean"]}]
    case("rows with form tags / with decoded tags / under-covered", census(pop), (3, 2, 1))

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LockBusy as exc:
        sys.exit(str(exc))
