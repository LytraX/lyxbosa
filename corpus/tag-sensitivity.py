#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Write a human's sensitivity ruling onto a row, with the evidence that decided it.

WHY THIS EXISTS AND `adopt-decoded-tags.py` DOES NOT COVER IT
-------------------------------------------------------------
That tool adopts a tag set the row already records, in `deobfuscation.decoded_form_tags`.
The five rows this was written for record no `deobfuscation` block at all: they were tagged
`clean` by `sensitivity.classify()`, which has no decoder, and `clean` is that function's
DEFAULT BRANCH - `if not tags: tags.add("clean")`. Four are gzip streams and the fifth hides
its payload in a base64 literal, so every regex in the rule saw compressed noise and fell
through to the one tag that means *publish as-is*. There is nothing on the row to adopt;
what exists is bytes, a re-derivation over them, and a human who has read both.

So this tool writes a RULING. It is not a re-derivation and it is not an adoption:

  * the re-derivation is a floor. A tag may not be added unless `sensitivity.classify_deep`
    over the row's own bytes also produces it - or the ruling says `human` and gives its
    reason, which is how the tar-header finding below gets written down at all.
  * every tag the re-derivation DOES produce must be adjudicated. Added, rejected or held,
    with a reason for the second two. A tag that the machine proposes and the ruling passes
    over in silence is refused, because silence is what put these rows at `clean`.
  * `publishable` is not written. §4.4: `shard-gate.py` is the only thing allowed to
    compute it, and it is printed as the next step.

THE EVIDENCE GOES ON THE ROW, NOT ONLY IN A REPORT
--------------------------------------------------
Some of what decides a tag exists nowhere else. On one of these five the account name is in
the `uname` and `gname` field of all 256 tar member headers and in **zero** member paths and
**zero** member bodies: a member-level content scan sees nothing, and only reading the
container's own metadata finds it. A finding like that is lost the moment the session that
made it ends, so the ruling carries it and the index keeps it.

The row also carries the CAUSE, because §8 asks why a number moved and "the tag was wrong"
is not a cause. The cause is that the tagger has no decoder and `clean` is its default
branch; the rows record that in their own `sensitivity_tagged.cause`.

THREE ANSWERS ABOUT THE BYTES, NEVER TWO
----------------------------------------
`--bytes-map` supplies sha256 -> path. Each file is hashed and must equal the row's own
`sha256` before it is read, so a ruling can never be verified against the wrong bytes. Where
a row's bytes are not supplied the state is `unavailable`, which is reported and REFUSES the
write rather than passing quietly - the same rule `gate_provenance.verify()` follows and the
same failure (`cannot tell` reading as `fine`) that the whole provenance mechanism exists
for. A stranger who clones this repository has neither the bytes nor the maps; what they get
is the decision file, the evidence, and this refusal.

    corpus/tag-sensitivity.py --decisions corpus/taggings/2026-09-06-five-clean-rows.json \
        --index corpus/local/index-local.jsonl --bytes-map <out-of-repo json>
    corpus/tag-sensitivity.py ... --by cl --apply
    corpus/tag-sensitivity.py --inject
"""
import argparse, copy, datetime, hashlib, importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy   # noqa: E402

_sspec = importlib.util.spec_from_file_location("sensitivity_tag",
                                                os.path.join(HERE, "sensitivity.py"))
SENS = importlib.util.module_from_spec(_sspec)
_sspec.loader.exec_module(SENS)

import gate_provenance                                                     # noqa: E402

RECORD_KEY = "sensitivity_tagged"
WRITABLE = ("sensitivity", RECORD_KEY)

# What a ruling may say about one tag. `hold` is not a soft `reject`: a rejected tag has been
# ruled on and will not come back without new evidence, a held one is an open question with
# the evidence recorded beside it, and collapsing them would lose which of the two a future
# round is allowed to close by itself.
VERBS = ("add", "reject", "hold")


def load_decisions(path):
    d = json.load(open(path, encoding="utf-8"))
    for key in ("signed_off_by", "date", "cause", "rows"):
        if key not in d:
            raise ValueError("decision file has no %r" % key)
    return d


def _adjudication(dec):
    """{tag: (verb, reason)} for one row's ruling, or raise."""
    out = {}
    for verb in VERBS:
        block = dec.get(verb) or ([] if verb == "add" else {})
        items = ((t, None) for t in block) if verb == "add" else block.items()
        for tag, reason in items:
            if tag not in SENS.TAGS:
                raise ValueError("%s is not a tag sensitivity.py can emit" % tag)
            if tag in out:
                raise ValueError("%s is both %s and %s" % (tag, out[tag][0], verb))
            if verb != "add" and not (reason or "").strip():
                raise ValueError("%s is %sed with no reason" % (tag, verb))
            out[tag] = (verb, reason)
    return out


def derive(data):
    """The machine floor: what the rule says over these bytes, raw and decoded."""
    maps = [p for p in (os.path.join("trail-data", "incoming", "2026-09-03", "private",
                                     "account-mapping.json"),
                        os.path.join("trail-data", "incoming", "2026-09-03", "private",
                                     "infected-tree-mapping.json")) if os.path.exists(p)]
    if not maps:
        return None
    m = json.load(open(maps[0], encoding="utf-8"))
    ctx = SENS.build(m["mapping"], m["domains"])
    layers = SENS.vcm().decode_layers(data)
    raw = SENS.classify(data, ctx, set(m["domains"]))[0]
    deep, ev = SENS.classify_deep(data, ctx, set(m["domains"]), layers=layers)
    return {"rule_digest": SENS.digest(),
            "decoder": "verify-content-mask.decode_layers",
            "tools_digest": gate_provenance.tools_digest(),
            "raw_tags": sorted(raw),
            "deep_tags": sorted(deep),
            "layers_decoded": len(layers),
            "layer_methods": sorted({meth for meth, _ in layers}),
            "tags_only_in_layers": ev["_read"]["tags_only_in_layers"]}


def bytes_state(row, path):
    """('verified', data) | ('mismatch', None) | ('unavailable', None). Never two answers."""
    if not path or not os.path.exists(path):
        return "unavailable", None
    with open(path, "rb") as fh:
        data = fh.read()
    if hashlib.sha256(data).hexdigest() != row["sha256"]:
        return "mismatch", None
    return "verified", data


def _resolves(row, adj):
    """Held tags this ruling closes: {tag} that the row records as `held` and now decides.

    A ruling that resolves a hold moves the RECORD and not the tags, and that is a real
    change - an unresolved tag on a row is an open question and a rejected one is an answer.
    Without this the tool refuses it as "nothing would move" and the row keeps saying
    UNRESOLVED after somebody has ruled, which is the stale-record defect this corpus keeps
    finding, in the one field that exists to say what a human decided.
    """
    prior = set((row.get(RECORD_KEY) or {}).get("held") or {})
    return {t for t, (v, _r) in adj.items() if v in ("reject", "add")} & prior


def check(row, dec, derived, restate=False):
    """None, or why this ruling may not be written.

    `derived` may be None, which is the `unavailable` state and is itself a refusal: the
    floor is not optional, and a ruling written without it is a ruling nothing checked.
    """
    try:
        adj = _adjudication(dec)
    except ValueError as exc:
        return str(exc)
    if derived is None:
        return "the row's bytes were not verified, so the re-derivation floor is missing"
    have = set(row.get("sensitivity") or [])
    proposed = set(derived["deep_tags"]) - {"clean"}
    adds = {t for t, (v, _r) in adj.items() if v == "add"}

    unadjudicated = sorted(proposed - set(adj) - have)
    if unadjudicated:
        return ("the re-derivation proposes %s and the ruling does not say what to do with "
                "%s" % ("/".join(sorted(proposed)), "/".join(unadjudicated)))
    ungrounded = sorted(t for t in adds
                        if t not in proposed and (dec.get("human") or {}).get(t) is None)
    if ungrounded:
        return ("%s is added and the re-derivation over the row's own bytes does not "
                "produce it; a human-only tag needs an entry in `human` giving its basis"
                % "/".join(ungrounded))
    if not adds - have and not _resolves(row, adj) and not restate:
        return ("every added tag is already on the row and no recorded hold is resolved, "
                "so nothing would move")
    if restate:
        # A restate fills gaps in a record and may change nothing else. It exists because a
        # record can be incomplete relative to the decision it was written from, and the
        # only safe repair is to re-derive it from the signed decision rather than to edit
        # the row. So the adjudication it carries must ALREADY equal what the row records:
        # anything else is a new ruling and has to be written as one.
        prior = row.get(RECORD_KEY) or {}
        if not prior:
            return "--restate needs an existing record to restate; this row has none"
        want_rej = {t: r for t, (v, r) in adj.items() if v == "reject"}
        want_held = {t: r for t, (v, r) in adj.items() if v == "hold"}
        if (prior.get("rejected") or {}) != want_rej or (prior.get("held") or {}) != want_held:
            return ("--restate may not change a ruling: the decision file's rejections and "
                    "holds must already equal what the row records")
        new_ev = set(dec.get("evidence") or {}) - set(prior.get("evidence") or {})
        if not new_ev:
            return "--restate would add nothing to the record"
    missing = sorted(t for t in adds if not (dec.get("evidence") or {}).get(t))
    if missing:
        return "%s is added with no evidence recorded" % "/".join(missing)
    return None


def build(row, dec, derived, meta, by, at=None, restate=False):
    """(after_row, refusal). Exactly one is None."""
    if not by or not by.strip():
        return None, "an author is required: a tag has an owner like any other decision"
    bad = check(row, dec, derived, restate=restate)
    if bad:
        return None, bad
    adj = _adjudication(dec)
    have = set(row.get("sensitivity") or [])
    adds = {t for t, (v, _r) in adj.items() if v == "add"}
    merged = sorted((have | adds) - {"clean"}) or ["clean"]

    # A later ruling amends an earlier one; it does not erase what the earlier one recorded.
    # The first version of this function wrote a fresh record, and the ruling that closed a
    # hold on one row took the tar-header finding - a measurement that exists nowhere else -
    # off that row with it. Prior evidence is carried forward and the new ruling's entries
    # win per key; the record it replaces is kept whole under `supersedes`, one level deep so
    # the chain cannot grow without bound.
    prior = row.get(RECORD_KEY) or {}
    evidence = dict(prior.get("evidence") or {})
    evidence.update(dec.get("evidence") or {})
    human = dict(prior.get("human_basis") or {})
    human.update(dec.get("human") or {})

    after = copy.deepcopy(row)
    after["sensitivity"] = merged
    after[RECORD_KEY] = {
        "by": by.strip(),
        "at": (at or datetime.datetime.now().replace(microsecond=0)).isoformat(),
        "signed_off_by": meta["signed_off_by"],
        "decisions": os.path.basename(meta["_path"]),
        "was": sorted(have),
        # What the row was before the FIRST ruling, carried forward. `was` means "before
        # this write" and `supersedes` is one level deep, so a third ruling would otherwise
        # lose the origin - and the origin is the whole finding on these rows, which were
        # `clean` because the tagger has no decoder.
        "originally": sorted((prior.get("originally") if prior.get("originally") is not None
                              else prior.get("was")) or have),
        "added": sorted(adds - have),
        "rejected": {t: r for t, (v, r) in sorted(adj.items()) if v == "reject"},
        "held": {t: r for t, (v, r) in sorted(adj.items()) if v == "hold"},
        "resolved_holds": sorted(_resolves(row, adj)),
        "cause": meta["cause"],
        "evidence": evidence,
        "human_basis": human,
        "derived": derived,
    }
    if prior:
        sup = {k: v for k, v in prior.items() if k != "supersedes"}
        after[RECORD_KEY]["supersedes"] = sup
    return after, None


def assert_additive(before, after):
    """None, or what changed that should not have. Both directions, as always."""
    moved = sorted({k for k in set(before) | set(after) if before.get(k) != after.get(k)})
    extra = [k for k in moved if k not in WRITABLE]
    if extra:
        return "changed %s, which is outside %s" % ("/".join(extra), "/".join(WRITABLE))
    if "sensitivity" not in moved:
        # A ruling that only closes a hold, or a restate that only fills a gap, is
        # legitimate - and must still be a CHANGE. The record has to move, and either the
        # held set shrinks or the evidence grows, or this is a no-op write.
        before_rec = before.get(RECORD_KEY) or {}
        after_rec = after.get(RECORD_KEY) or {}
        closed = set(before_rec.get("held") or {}) - set(after_rec.get("held") or {})
        gained = set(after_rec.get("evidence") or {}) - set(before_rec.get("evidence") or {})
        if RECORD_KEY not in moved or not (closed or gained):
            return ("sensitivity did not move, no recorded hold was resolved and no "
                    "evidence was added")
    if not set(before.get("sensitivity") or []) - {"clean"} <= set(after["sensitivity"]):
        return "an existing sensitivity tag was dropped"
    # The defect that cost one row its tar-header finding. Evidence is the part of a record
    # that exists nowhere else, so a later ruling may add to it and may never drop a key.
    lost = sorted(set(((before.get(RECORD_KEY) or {}).get("evidence") or {}))
                  - set(((after.get(RECORD_KEY) or {}).get("evidence") or {})))
    if lost:
        return "dropped recorded evidence for %s" % "/".join(lost)
    if "publishable" in moved:
        return "wrote publishable, which only shard-gate.py may compute"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=os.path.join(HERE, "local", "index-local.jsonl"))
    ap.add_argument("--decisions")
    ap.add_argument("--bytes-map", help="json of sha256 -> path, out of repo like the maps")
    ap.add_argument("--by", default=None, help="who is writing the ruling")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--restate", action="store_true",
                    help="re-derive a record from a decision file it already agrees with, "
                         "to fill gaps in it. Changes no ruling and can only add evidence")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    if not a.decisions:
        return ap.error("--decisions is required unless --inject")

    meta = load_decisions(a.decisions)
    meta["_path"] = a.decisions
    paths = json.load(open(a.bytes_map)) if a.bytes_map else {}
    rows = read_jsonl(a.index)
    by_sha = {r["sha256"]: r for r in rows}

    print("decisions                 : %s" % os.path.basename(a.decisions))
    print("signed off by             : %s  (%s)" % (meta["signed_off_by"], meta["date"]))
    print("rows in the decision file : %d" % len(meta["rows"]))
    print("bytes offered             : %d" % len(paths))
    print()

    todo, refused = [], []
    states = {}
    for dec in meta["rows"]:
        sha = dec["sha256"]
        row = by_sha.get(sha)
        if row is None:
            refused.append((sha, "not in %s" % os.path.basename(a.index)))
            continue
        state, data = bytes_state(row, paths.get(sha))
        states[sha] = state
        derived = derive(data) if state == "verified" else None
        after, refusal = build(row, dec, derived, meta, a.by or "dry-run",
                               restate=a.restate)
        if refusal:
            refused.append((sha, "%s [bytes %s]" % (refusal, state)))
            continue
        rec = after[RECORD_KEY]
        todo.append((sha, rec["was"], after["sensitivity"], rec["added"],
                     sorted(rec["held"]), sorted(rec["rejected"]), state))

    print("%-14s %-22s %-34s %-16s %s" % ("row", "was", "becomes", "adds", "held/rejected"))
    for sha, was, new, added, held, rej, state in todo:
        print("%-14s %-22s %-34s %-16s held=%s rejected=%s  [bytes %s]"
              % (sha[:12], ",".join(was), ",".join(new), ",".join(added),
                 ",".join(held) or "-", ",".join(rej) or "-", state))
    for sha, why in refused:
        print("%-14s REFUSED: %s" % (sha[:12], why))
    print()
    print("rows to tag               : %d" % len(todo))
    print("rows refused              : %d" % len(refused))
    if refused:
        print("  a refusal is the result, not an obstacle: every one of them is a ruling")
        print("  this tool will not write, and the reason is printed above.")

    if not a.apply:
        print()
        print("dry run: nothing written. Re-run with --by <who> --apply.")
        return 1 if refused else 0
    if not a.by:
        return ap.error("--by is required to write")
    if refused:
        return sys.exit("refusing to write any row while %d ruling(s) are refused"
                        % len(refused))

    want = {sha for sha, *_ in todo}
    at = datetime.datetime.now().replace(microsecond=0)
    with index_lock(a.index):
        # Re-read inside the lock. A ruling checked against a stale copy of the row could
        # merge into a tag set nobody signed.
        rows = read_jsonl(a.index)
        n_before = len(rows)
        written = 0
        for i, r in enumerate(rows):
            if r["sha256"] not in want:
                continue
            dec = next(d for d in meta["rows"] if d["sha256"] == r["sha256"])
            state, data = bytes_state(r, paths.get(r["sha256"]))
            derived = derive(data) if state == "verified" else None
            after, refusal = build(r, dec, derived, meta, a.by, at,
                                   restate=a.restate)
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
    print("rows written              : %d" % written)
    print("`publishable` is NOT touched here - run")
    print("  corpus/shard-gate.py --fix %s" % os.path.relpath(a.index, os.getcwd()))
    print("which is the only thing allowed to compute it.")
    return 0


# ---------------------------------------------------------------------------------------
# Controls. Every refusal this design claims, paired with the write that proves the tool can
# also say yes - a tool made only of refusals passes a suite made only of refusals.
# ---------------------------------------------------------------------------------------

def inject():
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-64s %-24s %s" % (label, str(got)[:24],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    META = {"signed_off_by": "the operator", "date": "2026-09-06",
            "cause": "the tagger has no decoder and clean is its default branch",
            "_path": "probe.json"}

    def row(sens=("clean",)):
        return {"sha256": "0" * 64, "verdict": "malicious", "sensitivity": list(sens)}

    def derived(deep, raw=("clean",)):
        return {"rule_digest": "0" * 12, "decoder": "probe", "tools_digest": "0" * 12,
                "raw_tags": sorted(raw), "deep_tags": sorted(deep), "layers_decoded": 1,
                "layer_methods": ["base64"], "tags_only_in_layers": sorted(deep)}

    def dec(**kw):
        d = {"sha256": "0" * 64}
        d.update(kw)
        return d

    print("=== it must REFUSE these ===")
    case("no author",
         "refused" if build(row(), dec(add=["path"], evidence={"path": "e"}),
                            derived(["path"]), META, " ")[1] else "written", "refused")
    case("bytes not verified, so no re-derivation floor",
         "refused" if build(row(), dec(add=["path"], evidence={"path": "e"}),
                            None, META, "cl")[1] else "written", "refused")
    case("a tag outside sensitivity.TAGS",
         "refused" if build(row(), dec(add=["nonsense"]), derived(["path"]),
                            META, "cl")[1] else "written", "refused")
    case("a tag the re-derivation proposes and the ruling ignores",
         "refused" if build(row(), dec(add=["path"], evidence={"path": "e"}),
                            derived(["path", "pii"]), META, "cl")[1] else "written",
         "refused")
    case("a tag added that the re-derivation does not produce",
         "refused" if build(row(), dec(add=["secret"], evidence={"secret": "e"}),
                            derived(["path"]), META, "cl")[1] else "written", "refused")
    case("a rejected tag with no reason",
         "refused" if build(row(), dec(add=["path"], reject={"pii": ""},
                                       evidence={"path": "e"}),
                            derived(["path", "pii"]), META, "cl")[1] else "written",
         "refused")
    case("a held tag with no reason",
         "refused" if build(row(), dec(add=["path"], hold={"c2": "  "},
                                       evidence={"path": "e"}),
                            derived(["path", "c2"]), META, "cl")[1] else "written",
         "refused")
    case("the same tag both added and rejected",
         "refused" if build(row(), dec(add=["path"], reject={"path": "r"},
                                       evidence={"path": "e"}),
                            derived(["path"]), META, "cl")[1] else "written", "refused")
    case("an added tag with no evidence",
         "refused" if build(row(), dec(add=["path"]), derived(["path"]),
                            META, "cl")[1] else "written", "refused")
    case("nothing would move",
         "refused" if build(row(["path"]), dec(add=["path"], evidence={"path": "e"}),
                            derived(["path"]), META, "cl")[1] else "written", "refused")

    print()
    print("=== and WRITE these ===")
    after, refusal = build(row(), dec(add=["c2", "identity"],
                                      evidence={"c2": "e", "identity": "e"}),
                           derived(["c2", "identity"]), META, "cl")
    case("clean -> c2/identity", after["sensitivity"] if after else refusal,
         ["c2", "identity"])
    case("`clean` is dropped when anything else survives",
         "clean" not in (after["sensitivity"] if after else ["clean"]), True)
    case("the record carries what it was", after[RECORD_KEY]["was"], ["clean"])
    case("the record carries the cause", after[RECORD_KEY]["cause"], META["cause"])
    case("the record carries the re-derivation",
         after[RECORD_KEY]["derived"]["deep_tags"], ["c2", "identity"])
    case("the record carries who signed it off",
         after[RECORD_KEY]["signed_off_by"], "the operator")

    a2, _ = build(row(), dec(add=["identity"], reject={"pii": "one changelog word"},
                             hold={"c2": "not separable from plugin documentation"},
                             evidence={"identity": "tar uname/gname on all members"}),
                  derived(["c2", "identity", "pii"]), META, "cl")
    case("a held tag is NOT written into sensitivity", a2["sensitivity"], ["identity"])
    case("and the hold is recorded with its reason",
         list(a2[RECORD_KEY]["held"]), ["c2"])
    case("a rejected tag is recorded with its reason",
         list(a2[RECORD_KEY]["rejected"]), ["pii"])

    a3, _ = build(row(), dec(add=["identity"], human={"identity": "tar header field"},
                             evidence={"identity": "uname/gname, 256 of 256 members"}),
                  derived([]), META, "cl")
    case("a human-only tag is allowed when its basis is given",
         a3["sensitivity"] if a3 else "refused", ["identity"])
    case("and the basis is recorded", list(a3[RECORD_KEY]["human_basis"]), ["identity"])

    a4, _ = build(row(["c2"]), dec(add=["identity"], evidence={"identity": "e"}),
                  derived(["c2", "identity"]), META, "cl")
    case("an existing tag is kept, not replaced", a4["sensitivity"], ["c2", "identity"])
    a5, _ = build(row(), dec(add=["pii"], evidence={"pii": "e"}), derived(["pii"]),
                  META, "cl")
    case("pii is written like any other tag - NEVER is the gate's rule, not this one",
         a5["sensitivity"], ["pii"])

    print()
    print("=== a ruling that closes a HOLD moves the record, not the tags ===")
    held_row = dict(row(["identity"]))
    held_row[RECORD_KEY] = {"held": {"c2": "unresolved last round"},
                            "rejected": {}, "added": ["identity"]}
    ruling = dec(reject={"c2": "no evidence of attacker control", "pii": "one doc word"})
    a7, r7 = build(held_row, ruling, derived(["c2", "identity", "pii"]), META, "cl")
    case("a hold closed by a rejection is written",
         "written" if a7 else "refused: %s" % r7, "written")
    if a7:
        case("the tags do not move", a7["sensitivity"], ["identity"])
        case("the hold is gone", list(a7[RECORD_KEY]["held"]), [])
        case("and what it resolved is recorded", a7[RECORD_KEY]["resolved_holds"], ["c2"])
        case("the additive assertion accepts it",
             assert_additive(held_row, a7) or "clean", "clean")
    # The negative half: a row with NO recorded hold and nothing to add is still a no-op.
    plain = row(["identity"])
    case("no hold to resolve and nothing to add is still refused",
         "refused" if build(plain, dec(reject={"pii": "one doc word"}),
                            derived(["identity", "pii"]), META, "cl")[1] else "written",
         "refused")
    # And a write that leaves the hold in place must not pass the assertion.
    stalled = copy.deepcopy(a7) if a7 else None
    if stalled:
        stalled[RECORD_KEY]["held"] = {"c2": "unresolved last round"}
        case("a write that leaves the hold standing is caught",
             "caught" if assert_additive(held_row, stalled) else "MISSED", "caught")

    print()
    print("=== a later ruling amends an earlier record and never erases it ===")
    # The defect this closes: the ruling that closed the hold above wrote a fresh record and
    # took a tar-header finding - a measurement that exists nowhere else - off the row with
    # it. Evidence is carried forward, the new ruling wins per key, and the record it
    # replaces is kept whole.
    first = dict(row(["identity"]))
    first[RECORD_KEY] = {"held": {"c2": "unresolved"}, "rejected": {},
                         "added": ["identity"],
                         "evidence": {"identity": "uname/gname on 256 of 256 members"},
                         "human_basis": {"identity": "tar header field"}}
    a8, r8 = build(first, dec(reject={"c2": "no attacker control", "pii": "one doc word"}),
                   derived(["c2", "identity", "pii"]), META, "cl")
    case("the ruling is written", "written" if a8 else "refused: %s" % r8, "written")
    if a8:
        case("prior evidence survives it", list(a8[RECORD_KEY]["evidence"]), ["identity"])
        case("prior human basis survives it",
             list(a8[RECORD_KEY]["human_basis"]), ["identity"])
        case("and the record it replaced is kept whole",
             a8[RECORD_KEY]["supersedes"]["evidence"]["identity"][:12], "uname/gname ")
        deep = dict(first)
        deep[RECORD_KEY] = dict(first[RECORD_KEY], was=["clean"], originally=["clean"])
        a8b, _ = build(deep, dec(reject={"c2": "x", "pii": "y"}),
                       derived(["c2", "identity", "pii"]), META, "cl")
        case("a third ruling still knows the origin",
             a8b[RECORD_KEY]["originally"], ["clean"])
        case("the chain does not nest",
             "supersedes" in a8[RECORD_KEY]["supersedes"], False)
        case("the additive assertion accepts it",
             assert_additive(first, a8) or "clean", "clean")
    # The negative half, and the one that would have caught the original defect.
    dropped = copy.deepcopy(a8)
    dropped[RECORD_KEY]["evidence"] = {}
    case("a write that DROPS recorded evidence is caught",
         "caught" if assert_additive(first, dropped) else "MISSED", "caught")
    # And the new ruling's own evidence must win where the keys collide.
    a9, _ = build(first, dec(reject={"c2": "no attacker control", "pii": "one doc word"},
                             evidence={"identity": "restated, more precisely"}),
                  derived(["c2", "identity", "pii"]), META, "cl")
    case("a new entry wins over the one it supersedes",
         a9[RECORD_KEY]["evidence"]["identity"], "restated, more precisely")

    print()
    print("=== --restate fills a gap in a record and may not change a ruling ===")
    thin = dict(row(["identity"]))
    thin[RECORD_KEY] = {"held": {}, "rejected": {"c2": "no attacker control"},
                        "added": [], "evidence": {}, "human_basis": {}}
    same = dec(reject={"c2": "no attacker control"},
               evidence={"identity": "uname/gname on 256 of 256 members"})
    case("without --restate it is a no-op and is refused",
         "refused" if build(thin, same, derived(["c2", "identity"]), META, "cl")[1]
         else "written", "refused")
    a10, r10 = build(thin, same, derived(["c2", "identity"]), META, "cl", restate=True)
    case("with --restate it is written", "written" if a10 else "refused: %s" % r10,
         "written")
    if a10:
        case("and the gap is filled", list(a10[RECORD_KEY]["evidence"]), ["identity"])
        case("the additive assertion accepts a record that only gained evidence",
             assert_additive(thin, a10) or "clean", "clean")
        nothing = copy.deepcopy(thin)
        nothing[RECORD_KEY] = dict(thin[RECORD_KEY], by="someone else")
        case("but not one that gained nothing",
             "caught" if assert_additive(thin, nothing) else "MISSED", "caught")
    changed = dec(reject={"c2": "a DIFFERENT reason"},
                  evidence={"identity": "uname/gname on 256 of 256 members"})
    case("--restate may not change a recorded ruling",
         "refused" if build(thin, changed, derived(["c2", "identity"]), META, "cl",
                            restate=True)[1] else "written", "refused")
    case("--restate that would add nothing is refused",
         "refused" if build(thin, dec(reject={"c2": "no attacker control"}),
                            derived(["c2", "identity"]), META, "cl",
                            restate=True)[1] else "written", "refused")
    case("--restate on a row with no record at all is refused",
         "refused" if build(row(["identity"]), same, derived(["c2", "identity"]), META,
                            "cl", restate=True)[1] else "written", "refused")

    print()
    print("=== the write must be additive and must not compute publishability ===")
    base = dict(row(), publishable=True)
    after, _ = build(base, dec(add=["path"], evidence={"path": "e"}), derived(["path"]),
                     META, "cl")
    case("nothing outside sensitivity/%s moves" % RECORD_KEY,
         assert_additive(base, after) or "clean", "clean")
    t = copy.deepcopy(after)
    t["publishable"] = False
    case("writing publishable alongside is caught",
         "caught" if assert_additive(base, t) else "MISSED", "caught")
    t2 = copy.deepcopy(after)
    t2["verdict"] = "benign"
    case("a change outside the allow-list is caught",
         "caught" if assert_additive(base, t2) else "MISSED", "caught")
    b3 = row(["c2"])
    a6, _ = build(b3, dec(add=["identity"], evidence={"identity": "e"}),
                  derived(["c2", "identity"]), META, "cl")
    a6["sensitivity"] = ["identity"]
    case("dropping an existing tag is caught",
         "caught" if assert_additive(b3, a6) else "MISSED", "caught")
    case("a row that did not move is caught",
         "caught" if assert_additive(base, copy.deepcopy(base)) else "MISSED", "caught")

    print()
    print("=== the bytes question has three answers, never two ===")
    import tempfile
    tmp = tempfile.mkdtemp(prefix="tag-sensitivity-inject.")
    good = os.path.join(tmp, "good.bin")
    with open(good, "wb") as fh:
        fh.write(b"hello probe bytes")
    r = {"sha256": hashlib.sha256(b"hello probe bytes").hexdigest()}
    case("bytes that hash to the row", bytes_state(r, good)[0], "verified")
    bad = os.path.join(tmp, "bad.bin")
    with open(bad, "wb") as fh:
        fh.write(b"different bytes entirely")
    case("bytes that do not hash to the row", bytes_state(r, bad)[0], "mismatch")
    case("no bytes at all", bytes_state(r, None)[0], "unavailable")
    case("a path that does not exist",
         bytes_state(r, os.path.join(tmp, "nope.bin"))[0], "unavailable")
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

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
