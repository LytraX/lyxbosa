#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recompute `mask_tier` in a pseudonym map, and prove nothing else moved.

WHY THIS IS A TOOL AND NOT A ONE-LINER
--------------------------------------
`incident_mask.tiers()` decides how widely each identifier may be substituted, and the
answer is stored in the map rather than recomputed on read. So a fix to `tiers()` changes
nothing until the map is regenerated, and regeneration is a whole-file rewrite of the one
artefact that is not in git and cannot be recovered from it.

That rewrite is the dangerous part, not the tier arithmetic. There are three ways it can go
wrong, and this file exists because the first version of it got two of them wrong.

**It can narrow the leak check.** `pre-push-check.py` builds its identifier list from these
maps by way of `verify-infected-mask.identifiers()`. A regeneration that dropped a name would
shrink that list, and the leak check would then sweep for fewer identifiers and still print
SAFE TO PUSH - a checker weakened by the very maintenance meant to improve it, silently, in
the direction nothing else looks. §5.3's rule that a masker may never widen silently has a
mirror: a map may never narrow silently. `differences()` is the guard.

**It can weaken the masker without changing a single identifier.** `differences()` compares
the map's *contents* and has nothing to say about what the tiers mean. A demotion is a
narrower substitution rule by definition, so a regeneration can leave every name, every
pseudonym and every key in place and still stop masking real occurrences. That is not
hypothetical: the first run of this tool demoted one name correctly on collision grounds and
cost six masked occurrences over a census of real paths, and it took a human reading the
measurement to catch it, because all seven controls passed. `coverage()` is the guard, and
it refuses rather than warns.

**It can change the file's permissions.** The first version wrote with `open(tmp, "w")` and
`os.replace`, which takes the umask instead of the mode it replaced: a file holding 232
customer identifiers went from `0600` to `0644`. Nothing in the tool noticed, because the
assertion compared content and content was correct. `write_map_atomic()` mirrors
`indexio.write_jsonl_atomic` - read the mode, restore it on the temp file before the rename,
fsync the file and then the directory - and `--inject` asserts the MODE, not just the bytes.

REPORTING
---------
Moves are reported by SHAPE - length, whether the name is exactly a stock-CMS token, how many
stock tokens it prefixes - and never by spelling. This file is tracked, and writing an
account name into it puts the name in git exactly as surely as an unmasked row does. That has
happened five times in this repository, once inside the docstring of the script written to
catch it.
"""
import argparse, collections, datetime, importlib.util, json, os, shutil, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import incident_mask                                                    # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "vim_", os.path.join(HERE, "verify-infected-mask.py"))
_vim = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vim)


def bare_names(m):
    """The names `tiers()` is asked about: everything in `pairs()` that is not a domain.

    Read from `pairs()` rather than from `mask_tier`, so a name that was never tiered is
    tiered now instead of inheriting the map's omission.
    """
    return [k for k in incident_mask.pairs(m) if "." not in k]


def regenerate(m, vocab):
    """A new map, identical to `m` except for `mask_tier`."""
    new = json.loads(json.dumps(m))
    new["mask_tier"] = incident_mask.tiers(bare_names(m), vocab)
    return new


# ---------------------------------------------------------------------------------------
# The write.  Mirrors indexio.write_jsonl_atomic, for the same reasons and one more: this
# file is 0600 and must stay 0600.
# ---------------------------------------------------------------------------------------
def write_map_atomic(path, obj):
    """Replace `path` with `obj`, preserving the mode and surviving a crash.

    `tempfile.mkstemp` creates 0600, which happens to be right for this file and is NOT
    what makes it right - the mode is read from the file being replaced and restored
    explicitly, so a map that is deliberately group-readable stays that way and a map that
    is 0600 cannot be widened by a umask. Getting this right by accident is how it was got
    wrong: `open(tmp, "w")` produced 0644 under the default umask and nothing looked.
    """
    path = os.path.abspath(path)
    directory = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode & 0o777
    except FileNotFoundError:
        pass

    fd, tmp = tempfile.mkstemp(dir=directory,
                               prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=1, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        # Before the rename, never after: between `os.replace` and a later `chmod` the
        # file is live at the wrong mode, and that window is the whole bug.
        os.chmod(tmp, mode if mode is not None else 0o600)
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # Persist the rename, not just the bytes.
    dirfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


# ---------------------------------------------------------------------------------------
# Assertion one: the map's contents.  Everything above produces a candidate; this decides
# whether it may be written.
# ---------------------------------------------------------------------------------------
def differences(old, new):
    """Every way `new` is not `old` apart from tier VALUES. Empty means safe to write."""
    bad = []

    if _vim.identifiers(old) != _vim.identifiers(new):
        lost = _vim.identifiers(old) - _vim.identifiers(new)
        gained = _vim.identifiers(new) - _vim.identifiers(old)
        bad.append("identifiers() moved: %d lost, %d gained - pre-push-check.py would "
                   "sweep a different set" % (len(lost), len(gained)))

    if _vim.keep_tokens(old) != _vim.keep_tokens(new):
        bad.append("keep_tokens() moved: %d -> %d"
                   % (len(_vim.keep_tokens(old)), len(_vim.keep_tokens(new))))

    po, pn = incident_mask.pairs(old), incident_mask.pairs(new)
    if set(po) != set(pn):
        bad.append("pairs() key set moved: %d lost, %d gained"
                   % (len(set(po) - set(pn)), len(set(pn) - set(po))))
    else:
        moved = [k for k in po if po[k] != pn[k]]
        if moved:
            bad.append("%d pseudonym(s) changed - a pseudonym is the identity of a masked "
                       "row and may not be reassigned by a tier pass" % len(moved))

    for field in sorted(set(old) | set(new)):
        if field == "mask_tier":
            continue
        if field not in old or field not in new:
            bad.append("top-level field %r was %s" % (field,
                       "added" if field in new else "removed"))
        elif old[field] != new[field]:
            bad.append("top-level field %r changed; only mask_tier may move" % field)

    to, tn = old.get("mask_tier") or {}, new.get("mask_tier") or {}
    if set(to) != set(tn):
        bad.append("mask_tier key set moved: %d lost, %d gained"
                   % (len(set(to) - set(tn)), len(set(tn) - set(to))))
    return bad


# ---------------------------------------------------------------------------------------
# Assertion two: what the tiers MEAN.  A tier is a substitution width, so the only honest
# test of a tier change is how many real occurrences each width actually reaches.
# ---------------------------------------------------------------------------------------
def tier_matcher(name, tier):
    """The spans `incident_mask.Masker` would substitute for `name` at `tier`.

    Built by instantiating a real `Masker` over a one-name map rather than by re-deriving
    the regexes here. A second copy of the tier rules would be a second thing to keep in
    step, and a coverage check measuring a width the masker does not actually use is worse
    than no coverage check - it would license exactly the demotion it is meant to refuse.
    """
    mini = {"mapping": {name: "acct000"}, "domains": {},
            "mask_tier": {name: tier}, "keep": []}
    return incident_mask.Masker(mini)


def matched_spans(mk, text):
    """Start offsets this masker would rewrite. A set, so two positional rules that both
    match one occurrence count it once - `/home/<n>/` and `/home\\d/<n>/` are different
    patterns and the same occurrence."""
    starts = set()
    for rx in (mk.rx_domain, mk.rx_a, mk.rx_b, mk.rx_c):
        if rx:
            starts |= {mo.start(1) for mo in rx.finditer(text)}
    for rx, _ in mk.positional:
        starts |= {mo.start() for mo in rx.finditer(text)}
    return starts


def coverage(old, new, population):
    """Per changed name: how many real occurrences each tier reaches. Loss is a refusal.

    Measured per name and refused per name, not on the sum. A net figure lets one name's
    gain pay for another name's loss, and "the totals balance" is not a statement about the
    name that stopped being masked. The net is printed as well, because it is what the
    override is judged on.
    """
    to, tn = old.get("mask_tier") or {}, new.get("mask_tier") or {}
    out = []
    for name in sorted(tn):
        if to.get(name) == tn[name]:
            continue
        before = to.get(name)
        rec = {"name": name, "from": before, "to": tn[name], "before": 0, "after": 0}
        mb = tier_matcher(name, before) if before else None
        ma = tier_matcher(name, tn[name])
        for text in population:
            if mb is not None:
                rec["before"] += len(matched_spans(mb, text))
            rec["after"] += len(matched_spans(ma, text))
        rec["delta"] = rec["after"] - rec["before"]
        out.append(rec)
    return out


def load_population(roots, files):
    """Real paths to measure coverage over.

    Directory names as well as file names: incident-response directories are named after
    the account they were cut for, which is the form §5.3 records as having hidden three
    client names for a year, and a file-only population cannot see it.
    """
    out = []
    for f in files:
        with open(f, encoding="utf-8", errors="replace") as fh:
            out += [l.rstrip("\n") for l in fh if l.strip()]
    for r in roots:
        for base, _dirs, names in os.walk(r):
            out.append(base)
            out += [os.path.join(base, n) for n in names]
    return out


def shape(name, vocab):
    """How to describe an identifier without spelling it. See the module docstring."""
    low = name.lower()
    return {"length": len(low),
            "alphabetic": low.isalpha(),
            "exactly_a_stock_token": low in vocab,
            "stock_tokens_it_prefixes": sum(1 for t in vocab
                                            if t != low and t.startswith(low)),
            "stock_tokens_containing_it": sum(1 for t in vocab if low in t)}


WHY = {("C", "D"): "is exactly a stock-CMS vocabulary token, so the widest safe rule is "
                   "positional: C rewrote it as a whole word wherever it appeared",
       ("B", "D"): "is exactly a stock-CMS vocabulary token; B rewrote it anywhere after a "
                   "non-alphanumeric",
       ("A", "D"): "is exactly a stock-CMS vocabulary token; A rewrote it anywhere at all",
       ("A", "B"): "is contained in a stock token, so it may no longer substitute mid-token",
       ("A", "C"): "prefixes a stock token, so it needs a trailing non-letter guard",
       ("B", "A"): "is no longer contained in any stock token in this vocabulary",
       ("B", "C"): "prefixes a stock token, so it needs a trailing non-letter guard",
       ("C", "B"): "no longer prefixes any stock token in this vocabulary",
       ("C", "A"): "no longer collides with this vocabulary at all",
       ("D", "C"): "is no longer exactly a stock token"}


def report(old, new, vocab):
    to, tn = old.get("mask_tier") or {}, new.get("mask_tier") or {}
    moves = [(k, to.get(k), tn[k]) for k in sorted(tn) if to.get(k) != tn[k]]
    print("identifiers tiered            : %d" % len(tn))
    print("stored census                 : %s"
          % json.dumps(dict(sorted(collections.Counter(to.values()).items()))))
    print("regenerated census            : %s"
          % json.dumps(dict(sorted(collections.Counter(tn.values()).items()))))
    print("names whose tier moved        : %d" % len(moves))
    for name, a, b in moves:
        s = shape(name, vocab)
        print("  %s -> %s  a %d-character %s identifier, %s"
              % (a, b, s["length"], "alphabetic" if s["alphabetic"] else "mixed",
                 WHY.get((a, b), "collides differently against this vocabulary")))
        print("      exactly a stock token: %s · prefixes %d stock token(s) · "
              "contained in %d" % (s["exactly_a_stock_token"],
                                   s["stock_tokens_it_prefixes"],
                                   s["stock_tokens_containing_it"]))
    return moves


def report_coverage(rows, population):
    print("coverage population           : %d path(s)" % len(population))
    if not rows:
        print("  no tier moved, so no width changed and there is nothing to lose")
        return []
    lost = [r for r in rows if r["delta"] < 0]
    for r in rows:
        print("  %s -> %s  masks %d occurrence(s) where it masked %d  (%+d)%s"
              % (r["from"], r["to"], r["after"], r["before"], r["delta"],
                 "   <-- COVERAGE LOST" if r["delta"] < 0 else ""))
    net = sum(r["delta"] for r in rows)
    print("  net across every changed name: %+d occurrence(s)" % net)
    return lost


# ---------------------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------------------
def _toy_vocabulary():
    """A vocabulary for the controls.

    `--inject` deliberately does NOT require `--vocabulary`. Every control below tests the
    guards - the content assertion, the coverage refusal, the file mode - and not one of
    them depends on what a real stock CMS tree contains: the tiers are set by hand in each
    case precisely so the case is about the guard rather than about the arithmetic. Making
    the suite need a 158,675-file tree bought nothing and cost the only thing that matters
    about a control suite, which is that it gets run. Regeneration itself still requires a
    real vocabulary, because there the arithmetic is the point.
    """
    return {"admin", "index", "config", "upload", "media", "cache", "assets", "frobnix"}


def inject(m, vocab):
    fails = []

    def case(label, mutate, want_caught):
        cand = regenerate(m, vocab)
        if mutate:
            mutate(cand)
        bad = differences(m, cand)
        caught = bool(bad)
        ok = caught == want_caught
        print("  %-54s %-9s %s" % (label, "caught" if caught else "allowed",
                                   "ok" if ok else "WRONG"))
        if bad and ok and want_caught:
            print("        %s" % bad[0][:96])
        if not ok:
            fails.append(label)

    print("=== contents: each mutation must be CAUGHT ===")

    def drop_name(c):
        c["mapping"].pop(sorted(c["mapping"])[0])
    case("an account name dropped from the map", drop_name, True)

    def drop_domain(c):
        c["domains"].pop(sorted(c["domains"])[0])
    case("a domain dropped from the map", drop_domain, True)

    def repseudo(c):
        c["mapping"][sorted(c["mapping"])[0]] = "acct000"
    case("a pseudonym reassigned", repseudo, True)

    def edit_neighbour(c):
        c["keep"] = list(c.get("keep") or []) + ["something-new"]
    case("a neighbouring field edited", edit_neighbour, True)

    def drop_tier(c):
        c["mask_tier"].pop(sorted(c["mask_tier"])[0])
    case("a mask_tier key dropped", drop_tier, True)

    def truncate(c):
        c["account_hash"] = dict(list((c.get("account_hash") or {}).items())[:-1])
    case("an unrelated field quietly truncated", truncate, True)

    print()
    print("=== contents: the honest regeneration must be ALLOWED ===")
    case("mask_tier recomputed and nothing else", None, False)

    # -----------------------------------------------------------------------------------
    # Coverage. The guard that was missing when a correct-on-collision-grounds demotion
    # cost six masked occurrences and shipped anyway.
    # -----------------------------------------------------------------------------------
    print()
    print("=== coverage: a narrower tier that masks less must be REFUSED ===")
    # A name that is in neither map, fires no leak predicate and appears in no stock tree.
    # The obvious choice here was a real account name that happens to be an English word,
    # and pre-push-check.py refused this file over exactly that - the fifth time in this
    # repository that a masking tool named a customer in its own fixtures. Controls set the
    # tiers by hand, so the string never needed to be a real one.
    NAME = "frobnix"
    POP = ["/home/%s/public_html/index.php" % NAME,          # positional, every tier
           "/root/INCIDENT/ir-backup/%s_db.users.sql.gz" % NAME,   # C masks, D does not
           "/root/INCIDENT/%s-TO_UPLOAD.zip" % NAME,               # C masks, D does not
           "/var/lib/underwater/cache/asset.png",                  # no tier may touch this
           "/opt/stock/%s.php" % NAME]                             # C masks, D does not

    def cov(a, b):
        old = {"mapping": {NAME: "acct000"}, "domains": {}, "keep": [],
               "mask_tier": {NAME: a}}
        new = json.loads(json.dumps(old))
        new["mask_tier"] = {NAME: b}
        return coverage(old, new, POP)

    def ccase(label, a, b, want_loss):
        rows = cov(a, b)
        r = rows[0]
        lost = r["delta"] < 0
        ok = lost == want_loss
        print("  %-54s %d -> %d (%+d)  %s" % (label, r["before"], r["after"], r["delta"],
                                              "ok" if ok else "WRONG"))
        if not ok:
            fails.append(label)

    ccase("C -> D: the demotion that was rolled back", "C", "D", True)
    ccase("A -> D: the widest rule to the narrowest", "A", "D", True)
    ccase("D -> C: a promotion gains coverage", "D", "C", False)

    # An unchanged tier must produce no row at all rather than a zero one. The difference
    # matters: `coverage()` is what decides which names get measured, and a version that
    # returned a row per name would report a reassuring net of 0 for a map where nothing
    # was examined.
    unchanged = cov("C", "C")
    ok = unchanged == []
    print("  %-54s %s  %s" % ("C -> C: an unchanged tier is not measured at all",
                              "no row" if ok else "%d row(s)" % len(unchanged),
                              "ok" if ok else "WRONG"))
    if not ok:
        fails.append("an unchanged tier was measured as if it had moved")

    # The negative half of the coverage guard: it must not fire on a name whose occurrences
    # are all inside positional slots, or every future demotion would be refused on a
    # population that cannot tell the tiers apart.
    only_slots = ["/home/%s/public_html/x.php" % NAME, "/home2/%s/y.php" % NAME]
    rows = coverage({"mapping": {NAME: "acct000"}, "domains": {}, "keep": [],
                     "mask_tier": {NAME: "C"}},
                    {"mapping": {NAME: "acct000"}, "domains": {}, "keep": [],
                     "mask_tier": {NAME: "D"}}, only_slots)
    ok = rows[0]["delta"] == 0
    print("  %-54s %d -> %d (%+d)  %s" % ("C -> D where every occurrence is in a slot",
                                          rows[0]["before"], rows[0]["after"],
                                          rows[0]["delta"], "ok" if ok else "WRONG"))
    if not ok:
        fails.append("coverage fires on a demotion that loses nothing")

    # -----------------------------------------------------------------------------------
    # The file mode. Asserted rather than the content, because the content was correct
    # while the mode was wrong and that is exactly how it shipped.
    # -----------------------------------------------------------------------------------
    print()
    print("=== the write must preserve the mode it replaced ===")
    tmpd = tempfile.mkdtemp(prefix="regen-tiers-inject.")
    try:
        for want in (0o600, 0o640, 0o644):
            p = os.path.join(tmpd, "map-%o.json" % want)
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"mapping": {}, "domains": {}, "mask_tier": {}}, fh)
            os.chmod(p, want)
            write_map_atomic(p, {"mapping": {}, "domains": {}, "mask_tier": {"a": "D"}})
            got = os.stat(p).st_mode & 0o777
            content_ok = json.load(open(p))["mask_tier"] == {"a": "D"}
            ok = got == want and content_ok
            print("  %-54s %04o -> %04o  %s" % ("a map at %04o stays at %04o" % (want, want),
                                                want, got, "ok" if ok else "WRONG"))
            if not ok:
                fails.append("mode %04o was not preserved (got %04o)" % (want, got))
        # And the control on the control: a mode-blind write must be seen to fail this
        # test, or "the mode was preserved" is not being measured at all.
        p = os.path.join(tmpd, "blind.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({}, fh)
        os.chmod(p, 0o600)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:      # the original bug, reproduced
            json.dump({"mask_tier": {}}, fh)
        os.replace(tmp, p)
        widened = (os.stat(p).st_mode & 0o777) != 0o600
        print("  %-54s %s" % ("the pre-fix write is caught widening 0600",
                              "caught" if widened else "WRONG: umask hid it"))
        if not widened:
            fails.append("the mode assertion cannot observe the bug it was written for")
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)

    print()
    print("cases: 16 · passed: %d · failed: %d" % (16 - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", default=incident_mask.MAP_PATH)
    ap.add_argument("--vocabulary", action="append", default=[],
                    help="stock CMS tree, repeatable. Required to regenerate - the tiers "
                         "are only as good as the vocabulary they were measured against - "
                         "and deliberately NOT required by --inject")
    ap.add_argument("--coverage-root", action="append", default=[],
                    help="directory of real paths to measure tier coverage over, "
                         "repeatable. Files and directory names both")
    ap.add_argument("--coverage-paths", action="append", default=[],
                    help="file of newline-separated real paths, repeatable")
    ap.add_argument("--allow-coverage-loss", action="store_true",
                    help="write even though a changed tier masks fewer real occurrences. "
                         "A deliberate, recorded decision: 5.6 holds that leaving a name "
                         "costs everything and over-masking costs nothing")
    ap.add_argument("--apply", action="store_true", help="write the map; default is dry run")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()

    old = incident_mask.load_map(a.map)

    if a.inject:
        vocab = _toy_vocabulary()
        print("vocabulary                    : %d synthetic token(s); --inject does not "
              "read a stock tree" % len(vocab))
        print()
        return inject(old, vocab)

    if not a.vocabulary:
        return ap.error("--vocabulary is required to regenerate")
    vocab = set()
    for root in a.vocabulary:
        v = incident_mask.vocabulary(root)
        if not v:
            sys.exit("vocabulary root %s contributed no tokens; refusing to tier against "
                     "an empty collision reference" % root)
        print("vocabulary %-18s : %d token(s)" % (os.path.basename(root), len(v)))
        vocab |= v
    print("vocabulary, union             : %d token(s)" % len(vocab))
    print()

    new = regenerate(old, vocab)
    moves = report(old, new, vocab)
    print()

    bad = differences(old, new)
    print("assertion 1: nothing but mask_tier values moved")
    if bad:
        for b in bad:
            print("  REFUSING: %s" % b)
        return 1
    print("  identifiers() identical     : %d name(s)" % len(_vim.identifiers(old)))
    print("  keep_tokens() identical     : %d token(s)" % len(_vim.keep_tokens(old)))
    print("  pairs() identical           : %d substitution(s)" % len(incident_mask.pairs(old)))
    print("  every other field identical : %d field(s)" % (len(old) - 1))
    print()

    print("assertion 2: no changed tier masks fewer real occurrences")
    if moves and not (a.coverage_root or a.coverage_paths):
        print("  REFUSING: %d tier(s) moved and no coverage population was given."
              % len(moves))
        print("  A tier is a substitution width. Changing one without measuring what it")
        print("  stops reaching is how a demotion that was right on collision grounds cost")
        print("  six masked occurrences and passed every other control.")
        print("  Pass --coverage-root <tree> or --coverage-paths <file>.")
        return 1
    population = load_population(a.coverage_root, a.coverage_paths)
    rows = coverage(old, new, population)
    lost = report_coverage(rows, population)
    if lost and not a.allow_coverage_loss:
        print()
        print("  REFUSING: %d changed name(s) mask fewer real occurrences than before."
              % len(lost))
        print("  5.6: over-masking costs nothing and leaving a name costs everything, so a")
        print("  measured loss is not a trade this tool may make on its own. Re-run with")
        print("  --allow-coverage-loss if it is a decision someone has actually taken.")
        return 1
    if lost:
        print()
        print("  --allow-coverage-loss: proceeding with a measured loss of %d occurrence(s)"
              % -sum(r["delta"] for r in lost))
    print()

    if not a.apply:
        print("dry run: nothing written. Pass --apply to write the map.")
        return 0

    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    backup = "%s.%s.bak" % (a.map, stamp)
    if os.path.exists(backup):
        sys.exit("backup %s already exists; refusing to overwrite it" % backup)
    shutil.copy2(a.map, backup)          # copy2 carries the mode across
    before_mode = os.stat(a.map).st_mode & 0o777
    write_map_atomic(a.map, new)

    # Read back and re-assert, mode included. Writing and trusting the write is the same
    # mistake as storing a derived value and trusting the store.
    back = incident_mask.load_map(a.map)
    after_mode = os.stat(a.map).st_mode & 0o777
    if differences(old, back) or back.get("mask_tier") != new["mask_tier"]:
        sys.exit("map on disk does not match what was asserted; backup is at %s" % backup)
    if after_mode != before_mode:
        sys.exit("map mode moved %04o -> %04o; backup is at %s"
                 % (before_mode, after_mode, backup))
    print("backup written                : %s (mode %04o)"
          % (backup, os.stat(backup).st_mode & 0o777))
    print("map rewritten                 : %s (%d tier(s) moved, mode %04o preserved, "
          "re-asserted after write)" % (a.map, len(moves), after_mode))
    return 0


if __name__ == "__main__":
    sys.exit(main())
