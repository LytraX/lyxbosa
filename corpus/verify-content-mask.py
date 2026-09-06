#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The independent gate over sample BYTES: §5.6's plaintext gate and encoded-layer gate.

`verify-infected-mask.py` asks whether an index ROW still names a customer.  This asks the
same question of the sample's own bytes, and of every layer those bytes yield to a static
decoder.  Two gates rather than one because §5.4 records that they catch different things:
seven samples passed the plaintext gate while an account name sat inside their encoded
payload, and "the absence of a plaintext hit is evidence the encoder worked, not evidence
the sample is clean".

WHAT IT SHARES, AND WITH WHAT
-----------------------------
It shares the *question* with `verify-infected-mask.py` - `identifiers()`, `keep_tokens()`
and `check()` are imported from it rather than restated - and it shares **nothing** with
`content_mask.py` or either row masker.  §5.3: "Verification must not share the masker's
regexes.  A self-check built from the same patterns passes while being wrong."  The imported
half is the check, not the masker, and it compiles no identifier into a regex at all: names
are compared with `str` operations over a segment vocabulary it enumerates for itself.

The decoder below is deliberately its own, and deliberately WIDER than the masker's.  The
masker only touches plain base64, because that is the only layer it can rewrite without
moving an offset.  A gate that decoded no more than the masker could repair would certify
exactly the samples the masker happened to reach, so this one also opens zlib, gzip, hex and
escape layers - the ones the masker must refuse.  When it finds an identifier in one of
those the sample is held, which is the correct outcome and the whole reason for the asymmetry.

WHAT IT NEVER RECORDS
---------------------
Categories and counts, never a name.  §5.3's seventh failure was a gate result stored in the
index - "a field whose contents are, by construction, the names of the identifiers the gate
just found.  Storing the finding stored the leak."

--inject IS THE NEGATIVE CONTROL, AND IT IS THE ONE THAT MATTERS HERE
---------------------------------------------------------------------
For a masker the interesting control is that the gate still fails on a masked sample when an
identifier is planted back into it.  A gate run only against output the masker produced is
testing that the masker agrees with itself; AGENTS.md's rule is that a check which has never
been observed to fail is not yet a check.  `--inject` takes real masked bytes, plants each
known leak form into the plaintext and into each encodable layer one at a time, and asserts
a leak is reported every time - and that the unmodified masked bytes stay silent.
"""
import argparse, base64, binascii, codecs, importlib.util, json, os, re, sys, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import finding_notes                                                     # noqa: E402

PRIVATE = os.path.join("trail-data", "incoming", "2026-09-03", "private")
INCIDENT_MAP = os.path.join(PRIVATE, "account-mapping.json")
LEGACY_MAP = os.path.join(PRIVATE, "infected-tree-mapping.json")


def _load_row_checker():
    spec = importlib.util.spec_from_file_location(
        "verify_infected_mask", os.path.join(HERE, "verify-infected-mask.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


V = _load_row_checker()

# ---------------------------------------------------------------------------------------
# The decoder.  Its own, and wider than the masker's - see the module docstring.  Nothing is
# executed: every branch is a pure decode, so a sample that only yields its payload at
# runtime correctly fails to decode here rather than being waved through.
# ---------------------------------------------------------------------------------------
B64_RUN = re.compile(rb"[A-Za-z0-9+/]{16,}={0,3}")
HEX_RUN = re.compile(rb"(?<![0-9A-Za-z])([0-9A-Fa-f]{24,})(?![0-9A-Za-z])")
ESC_RUN = re.compile(rb"(?:\\x[0-9A-Fa-f]{2}|\\[0-7]{1,3}){8,}")
CHR_RUN = re.compile(rb"(?:chr\(\s*\d{1,3}\s*\)\s*\.?\s*){6,}", re.I)
ZSTREAM = re.compile(rb"\x78[\x01\x9c\xda]|\x1f\x8b\x08")

MIN_CARRY = 8          # a decoded run shorter than this cannot hold a name worth finding


def _texty(b):
    if not b:
        return False
    ok = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return ok / float(len(b)) > 0.80


def _inflate(b):
    for fn in (zlib.decompress,
               lambda x: zlib.decompress(x, -15),
               lambda x: zlib.decompress(x, 16 + zlib.MAX_WBITS)):
        try:
            out = fn(b)
            if out:
                return out
        except Exception:
            pass
    return None


def decode_layers(data, depth=0, max_depth=4, seen=None):
    """Every layer these bytes yield to a pure static decode, as (method, bytes).

    Recursive, because a payload wrapped twice is one the masker's plaintext pass never saw
    either.  De-duplicated by content, because a file with two hundred base64 runs that all
    decode to the same alphabet is a report nobody finishes.
    """
    if seen is None:
        seen = set()
    if depth >= max_depth:
        return []
    found = []

    def add(method, out):
        if not out or len(out) < MIN_CARRY:
            return
        h = hash(out)
        if h in seen:
            return
        seen.add(h)
        found.append((method, out))

    for m in B64_RUN.finditer(data):
        s = m.group(0)
        try:
            raw = base64.b64decode(s + b"=" * (-len(s) % 4), validate=False)
        except Exception:
            continue
        inf = _inflate(raw)
        if inf is not None:
            add("base64+inflate", inf)
        elif _texty(raw):
            add("base64", raw)

    for m in HEX_RUN.finditer(data):
        try:
            out = binascii.unhexlify(m.group(1) if len(m.group(1)) % 2 == 0
                                     else m.group(1)[:-1])
        except Exception:
            continue
        if _texty(out):
            add("hex-string", out)

    for rx, name in ((ESC_RUN, "escape"), (CHR_RUN, "chr-sequence")):
        for m in rx.finditer(data):
            try:
                if name == "escape":
                    out = codecs.escape_decode(m.group(0))[0]
                else:
                    out = bytes(bytearray(int(x) for x in re.findall(rb"\d{1,3}", m.group(0))
                                          if int(x) < 256))
            except Exception:
                continue
            if _texty(out):
                add(name, out)

    for m in ZSTREAM.finditer(data):
        out = _inflate(data[m.start():])
        if out is not None and _texty(out):
            add("raw-inflate", out)

    nested = []
    for meth, out in found[:32]:
        for m2, o2 in decode_layers(out, depth + 1, max_depth, seen):
            nested.append((meth + "->" + m2, o2))
    return found + nested


# ---------------------------------------------------------------------------------------
# Secret-shaped literals.
#
# The identifier gates answer "is a customer named here" and say nothing about "is a
# credential stored here".  SOURCES.md records that hole as open and as the next round's
# job: "shard-gate.py reads index rows, not bytes, so it cannot verify a content claim - the
# check belongs at publish time, where the bytes are in hand."
#
# A gate over the masked bytes alone cannot close it, because §5.1 requires a secret to be
# replaced by a synthetic of the SAME SHAPE - so the output still contains something
# bcrypt-shaped, and a shape test cannot tell that one from the original.  What is checkable
# is the DIFFERENCE: every credential-shaped literal in the output must differ from every one
# in the input.  That is a statement about the masking rather than about the bytes, it needs
# no knowledge of whose secret it is, and it fails loudly when a credential form the masker
# does not cover survives untouched.
#
# The patterns are this file's own and describe SHAPES, never values.  Only counts leave
# this function; the literals themselves are compared in memory and discarded.
# ---------------------------------------------------------------------------------------
SECRET_SHAPES = [
    ("bcrypt", re.compile(rb"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}")),
    ("phpass", re.compile(rb"\$P\$[./A-Za-z0-9]{31}")),
    ("md5-crypt", re.compile(rb"\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}")),
    ("wp-credential", re.compile(rb"(?:DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|"
                                 rb"LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|"
                                 rb"LOGGED_IN_SALT|NONCE_SALT)\W{1,12}['\"]([^'\"]{2,})['\"]")),
    # No LEFT boundary, and `pwd` is in the list. Both are repairs, both measured.
    #
    # The lookbehind was `(?<![A-Za-z0-9_])`, and the tagger's `literal-password` has no left
    # boundary at all, so a password assigned to a variable whose NAME ENDS with the keyword
    # was tagged and not gated: `$user_password`, `$adminpassword`, `$pwd`. §5.6 already
    # rules that a lookaround in an identifier regex should err towards over-matching and
    # records two leaks from one that did not; this was the third, on credentials. For a
    # DIFFERENTIAL gate over-matching is the strict direction - every extra literal is one
    # more thing masking has to have changed - so widening cannot make this gate laxer.
    #
    # Measured over the 55 before/after pairs reachable on this machine: three rows go
    # PASS -> FAIL, two keep FAIL with five more carried literals each, and 50 do not move.
    ("quoted-credential",
     re.compile(rb"(?i)(?:password|passwd|pwd|pass|api_key|apikey|secret)"
                rb"(?![A-Za-z0-9_])\s*[=:]>?\s*['\"]([^'\"]{4,})['\"]")),
    # The gate had NO PEM shape at all. `-----BEGIN … PRIVATE KEY-----` was tagged by
    # `sensitivity.SECRET_PATTERNS` and invisible here, and a PEM block has a value - its
    # base64 body - so it is gateable and the gate simply did not look.
    #
    # A COMPLETE block is required: opening marker, at least one base64 body line, closing
    # marker. That is not fastidiousness, it is what the two rows this was written for
    # actually contain. Both carry 34 `BEGIN … PRIVATE KEY` markers and ZERO `END` markers;
    # 32 of the 34 sit inside docblock prose (`the headers, e.g. …`) in a vendor crypto
    # library quoted by a scan report. A header-only shape would fail both rows on
    # documentation, which is the flood §5.3 records rather than a gate.
    ("pem-private-key",
     re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----[\r\n]+"
                rb"((?:[A-Za-z0-9+/=]{16,}[ \t]*[\r\n]+)+)"
                rb"-----END [A-Z ]*PRIVATE KEY-----")),
]


def secret_literals(data, with_layers=True, layers=None):
    """Every credential-shaped literal in the bytes and in each decoded layer.

    Returns a set of (shape, value).  Callers compare two of these and record the SIZE of
    the intersection; nothing here is ever written down.

    `layers` lets a caller that has already decoded these bytes pass the result in.
    `secret_gate` needs both the literals and the layer SET, and decoding twice for the two
    questions doubled the cost of the most expensive thing in the gate - on a 1.2 MB sample
    that yields ~1,250 layers it is the difference between seconds and minutes.
    """
    out = set()
    blobs = [data]
    if with_layers:
        blobs += [b for _, b in (decode_layers(data) if layers is None else layers)]
    for blob in blobs:
        for shape, rx in SECRET_SHAPES:
            for m in rx.finditer(blob):
                out.add((shape, m.group(rx.groups) if rx.groups else m.group(0)))
    return out


# The marker every synthetic value carries when its length allows one. Restated here rather
# than imported: this module shares nothing with the masker by design (§5.3), and importing
# `content_mask.MARKER` to decide whether the masker made something would be the self-check
# built from the masker's own constants that §5.3 forbids. It is asserted equal to the
# masker's in `inject()`, which is the right relationship - agreement proved rather than
# assumed.
SYNTHETIC_MARKER = b"mask"


def _layer_set(layers):
    """The decoded layers as a set of blobs, so two decodes can be compared for identity."""
    return {b for _m, b in layers}


def secret_gate(before, after):
    """(ok, result) - did every credential-shaped literal actually change, and did masking
    avoid adding one of its own?

    THE GATE USED TO BE DIFFERENTIAL IN ONE DIRECTION ONLY
    ------------------------------------------------------
    It asserted that no credential-shaped literal in the output is byte-identical to one in
    the input, and said nothing about the count going UP. A gate that can only fail one way
    is the defect this corpus keeps finding - the same shape as the regex that matched
    `/home/` and not `/home2/`, and as the publishability gate that could see over-claimed
    and not under-claimed. One row was observed at 23 credential-shaped literals after
    masking where it had 22 before, and nothing in the tree asked about it for a round.

    WHY THE RULE IS ABOUT THE COUNT AND NOT ABOUT THE SET, MEASURED
    ---------------------------------------------------------------
    §5.1 requires a masked secret to keep its shape, so a correctly masked credential IS a
    new credential-shaped literal: on one row eleven wp-config literals go in and eleven
    different ones come out. A rule phrased over the SET - "no literal in the output that was
    not in the input" - therefore fires on masking working, and the obvious repair is to
    exclude the synthetics the masker can be shown to have made, which is what
    `SYNTHETIC_MARKER` identifies. **Measured, that repair is not enough and the set rule is
    not usable:** over the 132 masked local rows it refuses **36**, because a synthetic
    shorter than seven characters has no room for the marker and cannot be attributed at all.
    A quarter of the masked population blocked on a rule whose failures are mostly the masker
    doing its job is not a gate, it is a flood.

    The COUNT rule has none of that trouble, because a one-for-one replacement leaves the
    count where it was. Over the same 132 rows exactly **one** has more literals after than
    before. So the rule armed here is the count, and the set arithmetic is recorded beside it
    -`secret_literals_added`, `_by_the_masker`, `_unattributed` - measured and not armed,
    which is this corpus's standing order for a rule whose blast radius it has just measured.

    WHAT THE ONE OBSERVED INCREASE ACTUALLY WAS, MEASURED RATHER THAN ASSUMED
    -------------------------------------------------------------------------
    Not a marked synthetic. `secret_literals()` counts over the plaintext AND every decoded
    layer, and **the decoded-layer population is not stable under masking**: on that row the
    masker changed four bytes inside one base64 region, the region re-encoded, and the
    `base64+inflate` layers nested below it decoded differently - 23 layers became 16, nine
    disappeared and two appeared, and one of the two carries a ten-character array key that
    the `wp-credential` pattern reads as a credential. `before` and `after` were censuses of
    two different populations, which is §11 exactly.

    So the two causes are recorded apart, and only one of them is this gate's verdict:

      * a literal byte-identical in both is a carry-over, whatever the layer population did.
        FAIL, unchanged.
      * MORE literals after than before, with the decoded-layer population UNCHANGED, is
        masking adding one to a population the two counts can both speak for. FAIL.
      * the same increase on a row whose decoded-layer set MOVED is not comparable. It is
        recorded with `literal_population_comparable: false`, and the decision belongs to
        `shard-gate.py` under its own reason, where §8 can count the cause separately.
        Failing it here as well would put two reasons on one cause, which is the
        double-counted denominator SOURCES.md records the blocker tally standing 14 out for.

    WHAT THE RECORDED BLOCK MEANS, WHICH USED TO BE A `note` KEY IN THE RESULT
    --------------------------------------------------------------------------
    Counts and shapes only. A credential-shaped literal remaining after masking is a
    synthetic one by construction, and §7.2's shard scan will still see its shape. Additions
    are measured over the plaintext and every decoded layer, and that layer population is
    not stable under masking - see `literal_population_comparable`.

    That paragraph was a `note` key in the dict this returns, and it is a docstring now
    because it was recorded on nobody. `mask-samples.py` writes a named twelve fields and
    `remeasure-gates.recorded_form` narrows to the same twelve, so no current writer stored
    it; it survived only on 8 rows from an earlier build, which recorded thirteen keys where
    124 recorded twelve. `gate_evidence.compare_gate` compares the keys the ROW holds, so
    those two schemas could be compared differently the moment this text moved, and the only
    thing making that harmless was that the text sat inside a `gate_provenance.TOOLS` module
    and could not move without every stamp going stale in the same instant. Deleting the key
    is what closes that: the 8 rows read `evidence-moved` once, reconcile to twelve through
    `recorded_form`, and there is no second schema left to fork.
    """
    layers_before, layers_after = decode_layers(before), decode_layers(after)
    b = secret_literals(before, layers=layers_before)
    a = secret_literals(after, layers=layers_after)
    carried = b & a
    added = a - b
    marked = {(s_, v) for s_, v in added
              if SYNTHETIC_MARKER in (v if isinstance(v, bytes) else str(v).encode()).lower()}
    unattributed = added - marked
    lb, la = _layer_set(layers_before), _layer_set(layers_after)
    comparable = lb == la
    increased = len(a) > len(b) and comparable
    res = {
        "secret_gate": "FAIL" if (carried or increased) else "PASS",
        "secret_literals_before": len(b),
        "secret_literals_after": len(a),
        "secret_literals_carried_over": len(carried),
        "secret_literals_added": len(added),
        "secret_literals_added_by_the_masker": len(marked),
        "secret_literals_added_unattributed": len(unattributed),
        "shapes_carried_over": sorted({s_ for s_, _ in carried}),
        "shapes_added_unattributed": sorted({s_ for s_, _ in unattributed}),
        "shapes_remaining": sorted({s_ for s_, _ in a}),
        "decoded_layers_before": len(lb),
        "decoded_layers_after": len(la),
        # False means the two counts above are censuses of DIFFERENT populations, so an
        # increase is not by itself evidence that masking made anything.
        "literal_population_comparable": comparable,
    }
    return (not carried and not increased), res


# ---------------------------------------------------------------------------------------
# The gates.
# ---------------------------------------------------------------------------------------
def _hits(text, ids, keep):
    contained, truncated, _ = V.check([{"sha256": "0" * 64, "bytes": text}], ids, keep)
    return contained, truncated


def _kind(ident):
    """What SHAPE of identifier was found.  Never which one - §5.3's seventh failure."""
    return "domain" if "." in ident else "acct"


def _profile(pairs):
    """The facts that decide what a finding is worth, recorded instead of a verdict.

    THIS STARTED AS A CONFIDENCE GRADE AND THE GRADE DID NOT SURVIVE MEASUREMENT.
    The plan was to call a hit from an identifier of six characters or more "high
    confidence" - it comes from `_is_a_leak`'s containment rule - and a shorter one "low",
    since the short rule is the whole-ALPHABETIC-run test and looks cheap. A null model over
    random base64 supported it: 660 trials of 98,473 bytes produced 0.23 short-name hits per
    trial and 0.0015 containment hits, about 150 to 1.

    **Random base64 was the wrong null.** Decoded layers are frequently code - a PHP
    function-name table, a plugin manifest, a wordlist - and code is where an account name
    that is also an English fragment collides. Re-run against 8,000 stock CMS files, which
    contain no customer of ours by construction so every hit is a false positive: 127 hits
    across 104 files. On realistic content the long rule is not meaningfully safer than the
    short one, and a label saying otherwise would have been a licence rather than a
    measurement. The case that caught it was real: a six-character account name sitting
    inside `imagick_...` in a 473 KB decoded function table, which the length rule would
    have called high confidence.

    **`FP_NOTE` said 36 came from identifiers of 6+ characters and `--stock-fp` printed 52;
    the note now says 52 and the note is no longer in this file.** Regenerated 2026-09-06,
    every other figure reproduced to the digit - 127 hits, 104 files, 1.30%, and 83 `exact`
    / 20 `begins` / 24 `contains` - and the 52 reproduces again today. 36 was `begins` (20)
    plus `contains` at 6+ (16) and omitted the 16 `exact` hits at 6+. Both figures are true
    of different questions and the note stated the narrower one without its qualifier, which
    matters when the finding being weighed IS a 6-character `begins` hit: it understated the
    population that hit belongs to by 16, and all 20 `begins` false positives in the table
    come from identifiers of 6+ characters.

    The note now carries the split it was missing - 16 `exact`, 20 `begins`, 16 `contains`
    at 6+ - and lives in `fp-note.txt`, which the AST digest does not read. It could not be
    corrected before because it was a module-level assignment in a file inside
    `gate_provenance.TOOLS`: fixing four characters of prose moved the `tools` digest and
    put all 139 stamped rows into re-measurement. Relocating it costs that re-measurement
    once and then never again.

    That is §11 exactly - a denominator enumerated by a process that does not resemble the
    population bounds the result and not reality - so no grade is emitted. What is recorded
    is the evidence a human needs and the gate verdict is unchanged: lengths, positions, the
    size of the segment the identifier sits in, and the layer that carried it. A `contains`
    hit inside a 25-character segment reads differently from an `exact` hit on its own, and
    now the row says which it was without ever naming the identifier.
    """
    contained, truncated = pairs
    idents = {i for _, i, _, _, _ in contained} | {i for _, _, i, _ in truncated}
    return {"distinct_identifiers": len(idents),
            "kinds": sorted({_kind(i) for i in idents}),
            "occurrences": len(contained) + len(truncated),
            # Lengths and positions, never names. These are what decide what the finding is
            # worth, and neither identifies anyone.
            "identifier_lengths": sorted({len(i) for i in idents}),
            "positions": sorted({p for _, _, _, _, p in contained}
                                | ({"truncation"} if truncated else set())),
            "segment_lengths": sorted({len(seg) for seg, _, _, _, _ in contained}),
            "false_positive_note": FP_NOTE}


# The two notes the findings carry, loaded from their own files rather than written here.
#
# Both used to be string literals in this file, and this file is one of the six in
# `gate_provenance.TOOLS`, so every word of them was inside the AST the `tools` digest is
# taken over. A prose repair therefore invalidated every provenance stamp - which is why the
# false-positive figure was wrong for a round and could not be fixed, and why the identifier
# note's second clause stayed wrong for two while `shard-gate.py` documented the price. A
# descriptive note is not behaviour and must not be able to do that.
#
# The AST holds the FILENAME and the loader, which are behaviour; the prose is data. The
# loader is `finding_notes.py`, which is deliberately outside `TOOLS` - it decides no
# verdict - and which the five modules building finding-shaped fixtures now read from too,
# so a fixture cannot go on asserting text the generator has stopped writing.
#
# Editing either file moves nothing, and `corpus/digest-controls.py --inject` is the control
# that says so; `corpus/finding_notes.py --inject` is the one that says the generator and
# the fixtures still agree. Neither lives here, because an argparse branch added to this
# file would move the `tools` digest to install a check whose subject is that prose edits do
# not do that.
FP_NOTE_PATH = finding_notes.FP_NOTE_PATH
FP_NOTE = finding_notes.FP_NOTE


def stock_fp(ids, keep, roots, sample=8000, seed=4242):
    """The null model that matters, regenerated rather than quoted.

    Stock CMS trees contain no customer of ours, so every hit is a false positive. This is
    the same reference `incident_mask.collisions()` uses and for the same reason.
    """
    import random
    files = []
    for root in roots:
        for base, _dirs, names in os.walk(root):
            for n in names:
                p = os.path.join(base, n)
                try:
                    if 200 <= os.path.getsize(p) <= 2000000:
                        files.append(p)
                except OSError:
                    pass
    random.Random(seed).shuffle(files)
    by = {}
    scanned = hitfiles = 0
    for p in files[:sample]:
        try:
            data = open(p, "rb").read()
        except OSError:
            continue
        scanned += 1
        c, t = _hits(data.decode("latin-1"), ids, keep)
        if c or t:
            hitfiles += 1
        for seg, ident, _n, _s, pos in c:
            by["len=%d %s" % (len(ident), pos)] = by.get("len=%d %s" % (len(ident), pos), 0) + 1
        for _v, _l, ident, _s in t:
            by["len=%d truncation" % len(ident)] = by.get("len=%d truncation" % len(ident), 0) + 1
    return {"files_scanned": scanned, "files_with_a_hit": hitfiles,
            "total_false_positives": sum(by.values()),
            "by_class": dict(sorted(by.items(), key=lambda kv: -kv[1]))}


def base_rate(ids, keep, size=98473, trials=60, seed=20260906):
    """The null model the grading rests on, runnable rather than quoted.

    A figure written into a comment is a figure nobody can challenge. This regenerates it:
    random base64 of `size` bytes, the real identifier set, the real predicate.
    """
    import random
    rng = random.Random(seed)
    fired = 0
    total = 0
    by_len = {}
    for _ in range(trials):
        blob = base64.b64encode(rng.randbytes(size * 3 // 4)).decode()[:size]
        c, t = _hits(blob, ids, keep)
        n = len(c) + len(t)
        total += n
        if n:
            fired += 1
        for i in ({i for _, i, _, _, _ in c} | {i for _, _, i, _ in t}):
            by_len[len(i)] = by_len.get(len(i), 0) + 1
    return {"trials": trials, "bytes_each": size,
            "trials_with_a_hit": fired, "mean_hits": total / trials,
            "hits_by_identifier_length": dict(sorted(by_len.items())),
            "containment_hits": sum(v for k, v in by_len.items()
                                    if k >= V.LONG_ENOUGH_TO_BE_ONLY_A_NAME)}


def gate(data, ids, keep):
    """(ok, result) for one sample's bytes.

    `result` names the gate that failed, the shapes involved and how many, and nothing else.

    A finding records the evidence rather than a verdict about it - lengths, positions, the
    size of the segment the identifier sits in, the layer that carried it. See `_profile`
    for why no confidence grade is emitted: the one that was written for this round did not
    survive its own null model.
    """
    plain_c, plain_t = _hits(data.decode("latin-1"), ids, keep)
    layers = decode_layers(data)
    enc = []
    for meth, out in layers:
        c, t = _hits(out.decode("latin-1"), ids, keep)
        if c or t:
            enc.append((meth, c, t))

    res = {
        "plaintext_gate": "FAIL" if (plain_c or plain_t) else "PASS",
        "encoded_layer_gate": "PASS",
        "layers_decoded": len(layers),
        "layer_methods": sorted({m for m, _ in layers}),
    }
    if plain_c or plain_t:
        res["plaintext_finding"] = _profile((plain_c, plain_t))
        res["plaintext_finding"]["note"] = finding_notes.IDENTIFIER_NOTE
    if enc:
        allc, allt = [], []
        for _m, c, t in enc:
            allc += c
            allt += t
        res["encoded_layer_gate"] = "FAIL"
        res["encoded_layer_finding"] = _profile((allc, allt))
        res["encoded_layer_finding"]["methods"] = sorted({m for m, _, _ in enc})
        res["encoded_layer_finding"]["note"] = finding_notes.IDENTIFIER_NOTE
    ok = res["plaintext_gate"] == "PASS" and res["encoded_layer_gate"] == "PASS"
    return ok, res


def load_ids(map_paths):
    """(identifiers, keep) merged over every map given.

    Both maps by default, because §5.3's third failure was a masker that handled one
    identifier class and a check that therefore only ever asked about that class.  A sample
    collected in this incident can still carry a name from the legacy tree - the two
    collections are of the same provider's hosts - and a gate run against one map cannot
    say anything at all about the other.
    """
    ids, keep = set(), set()
    for p in map_paths:
        with open(p, encoding="utf-8") as fh:
            m = json.load(fh)
        ids |= V.identifiers(m)
        keep |= V.keep_tokens(m)
    return ids, keep


# ---------------------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------------------
PLANT = [
    ("account as a path segment",        "$p = '/home/%s/public_html/index.php';"),
    ("account under /home2",             "$p = '/home2/%s/public_html/x.php';"),
    ("underscore-encoded quarantine",    "$f = '_home_%s_public_html_wp-admin.php';"),
    ("account as a DB name prefix",      "define('DB_NAME', '%s_db');"),
    ("account glued to the end of a run", "$z = 'Backup%s0304.zip';"),
    ("account inside a URL path",        "$u = 'https://cdn.example.net/c/%s-jb.html';"),
    ("free prose, not a path",           "// seen across three accounts (%s and others)"),
]


def inject(ids, keep, sample=None):
    """Plant each leak form into MASKED bytes and assert the gate still says so.

    The positive half is planted into the plaintext AND into a base64 layer, because those
    are two different gates and only one of them was ever observed to fail.  The negative
    half is the masked sample untouched: a gate that fires on everything certifies nothing.
    """
    longest = max((i for i in ids if len(i) >= 6), key=len, default=None)
    if longest is None:
        print("no identifier long enough to inject with")
        return 1
    base = open(sample, "rb").read() if sample else (
        b"<?php\n// an ordinary masked sample\n$a = 'wp-content/plugins/x.php';\n"
        b"$b = 'user@example.com';\n$c = '/home/acct01/public_html/index.php';\n"
        b"$d = '" + base64.b64encode(b"/home/acct01/public_html//index.php") + b"';\n")
    failures = []

    ok, res = gate(base, ids, keep)
    print("   -  %-42s %s" % ("the masked bytes, untouched",
                              "silent" if ok else "FIRED (false positive): %s"
                              % json.dumps(res)))
    if not ok:
        failures.append("fires on the unmodified masked sample")

    # ------------------------------------------------------------------------------------
    # What a finding records. Both identifiers are chosen by LENGTH at run time and never
    # written down: length is the variable under test, and spelling one into this file would
    # put a customer name in git.
    # ------------------------------------------------------------------------------------
    shortest = min((i for i in ids if len(i) < V.LONG_ENOUGH_TO_BE_ONLY_A_NAME
                    and i.isalpha()), key=len, default=None)
    print()
    print("=== a finding records the evidence a human needs, and never a name ===")
    for label, ident in (("a short identifier", shortest), ("a long identifier", longest)):
        if ident is None:
            continue
        buf = b"<?php $x='" + base64.b64encode(b"aaaa9" + ident.encode() + b"9aaaa") + b"';"
        _, r = gate(buf, ids, keep)
        f = r.get("encoded_layer_finding") or {}
        has = all(k in f for k in ("identifier_lengths", "positions", "segment_lengths",
                                   "false_positive_note"))
        named = any(ident.lower() in json.dumps(f).lower() for _ in (0,))
        good = r["encoded_layer_gate"] == "FAIL" and has and not named
        print("   +  %-42s %s" % (label + " in a base64 layer",
                                  "FAIL, evidence recorded, no name" if good else "WRONG"))
        if not good:
            failures.append("finding shape: " + label)


    print("planted into the plaintext")
    for name, form in PLANT:
        planted = base + b"\n" + (form % longest).encode("latin-1") + b"\n"
        ok, res = gate(planted, ids, keep)
        caught = res["plaintext_gate"] == "FAIL"
        print("   +  %-42s %s" % (name, "caught" if caught else "MISSED"))
        if not caught:
            failures.append("plaintext: " + name)

    print()
    print("planted inside an encoded layer, which the plaintext gate cannot see")
    for meth, wrap in (
            ("base64", lambda b: base64.b64encode(b)),
            ("base64, unpadded", lambda b: base64.b64encode(b).rstrip(b"=")),
            ("base64+deflate", lambda b: base64.b64encode(zlib.compress(b))),
            ("hex string", lambda b: binascii.hexlify(b)),
    ):
        payload = ("/home/%s/public_html/index.php" % longest).encode("latin-1")
        planted = base + b"\n$e = '" + wrap(payload) + b"';\n"
        ok, res = gate(planted, ids, keep)
        caught = res["encoded_layer_gate"] == "FAIL"
        clean_plain = res["plaintext_gate"] == "PASS"
        print("   +  %-42s %s%s" % ("identifier inside %s" % meth,
                                    "caught" if caught else "MISSED",
                                    "" if clean_plain else "  (plaintext gate also fired)"))
        if not caught:
            failures.append("encoded: " + meth)

    print()
    print("the differential secret gate, both directions")
    for name, before, after, want_fail in (
            ("a password literal left unchanged",
             b"$password = 'abcd1234';", b"$password = 'abcd1234';", True),
            ("a bcrypt hash left unchanged",
             b"$h = '$2y$10$" + b"a" * 53 + b"';", b"$h = '$2y$10$" + b"a" * 53 + b"';", True),
            ("a credential inside a base64 layer left unchanged",
             b"$x='" + base64.b64encode(b"$password = 'abcd1234';") + b"';",
             b"$x='" + base64.b64encode(b"$password = 'abcd1234';") + b"';", True),
            ("a password literal actually replaced",
             b"$password = 'abcd1234';", b"$password = 'zzzz9999';", False),
            ("no credential on either side",
             b"<?php echo 1;", b"<?php echo 1;", False),
            # The second direction. The gate said nothing about the count going UP for
            # nine rounds, and one row sat at 23-against-22 with nothing asking.
            ("masking left MORE literals than it found",
             b"<?php echo 1;", b"$password = 'abcd1234';", True),
            ("masking left FEWER: this gate is about adding, not about losing",
             b"$password = 'abcd1234';", b"<?php echo 1;", False),
            # And the case that decides the rule's shape. §5.1 makes a masked credential a
            # NEW credential-shaped literal, so a rule over the SET fires on masking
            # working. Eleven in, eleven out, none carried: the count holds and the gate
            # must stay silent. Over the 132 masked local rows a set rule refuses 36.
            ("eleven credentials replaced one for one",
             b"".join(b"define('DB_PASSWORD', 'pw%02d1234');" % i for i in range(11)),
             b"".join(b"define('DB_PASSWORD', 'zq%02d8877');" % i for i in range(11)),
             False),
   
            # ------------------------------------------------------------------------
            # The two narrownesses repaired in this commit. Each is a pair: the credential
            # the gate could not see must now fail it, and the thing that must NOT fail it
            # is beside it - a widened pattern that fires on documentation is a flood, not
            # a gate.
            # ------------------------------------------------------------------------
            ("a password on a name ENDING with the keyword, left unchanged",
             b"$user_password = 'abcd1234';", b"$user_password = 'abcd1234';", True),
            ("the same password actually replaced",
             b"$user_password = 'abcd1234';", b"$user_password = 'zzzz9999';", False),
            ("a password on a GLUED name, left unchanged",
             b"$adminpassword='abcd1234';", b"$adminpassword='abcd1234';", True),
            ("`pwd`, which this gate had no keyword for, left unchanged",
             b"$pwd = 'abcd1234';", b"$pwd = 'abcd1234';", True),
            ("a complete PEM private key left unchanged",
             b"-----BEGIN RSA PRIVATE KEY-----\nQUFBQUFBQUFBQUFBQUFB\n"
             b"-----END RSA PRIVATE KEY-----",
             b"-----BEGIN RSA PRIVATE KEY-----\nQUFBQUFBQUFBQUFBQUFB\n"
             b"-----END RSA PRIVATE KEY-----", True),
            ("a complete PEM private key actually replaced",
             b"-----BEGIN RSA PRIVATE KEY-----\nQUFBQUFBQUFBQUFBQUFB\n"
             b"-----END RSA PRIVATE KEY-----",
             b"-----BEGIN RSA PRIVATE KEY-----\nWlpaWlpaWlpaWlpaWlpa\n"
             b"-----END RSA PRIVATE KEY-----", False),
            # The negative half that decides the PEM shape. Both rows this was written for
            # carry 34 BEGIN markers and no END marker at all, 32 of them inside docblock
            # prose. A header-only shape fails them on documentation.
            ("a PEM HEADER quoted in documentation, with no key body",
             b"# the headers, e.g. `-----BEGIN RSA PRIVATE KEY-----MIIBOgIBAAJBAK`\n",
             b"# the headers, e.g. `-----BEGIN RSA PRIVATE KEY-----MIIBOgIBAAJBAK`\n",
             False),
    ):
        ok, res = secret_gate(before, after)
        fired = res["secret_gate"] == "FAIL"
        good = fired == want_fail
        print("   %s  %-40s %s" % ("+" if want_fail else "-", name,
                                   ("caught" if fired else "MISSED") if want_fail
                                   else ("silent" if not fired else "FIRED")))
        if not good:
            failures.append("secret gate: " + name)

    # WHY the set rule cannot be rescued by excluding the masker's own synthetics, asserted
    # rather than argued. `SYNTHETIC_MARKER` is restated in this module because §5.3 forbids
    # a check built from the masker's constants; the control is where the two are proved
    # equal instead. And the marker only goes into IDENTIFIER substitutions - the masker's
    # credential replacements (`_value`, `_bcrypt`, `_phpass`, `_hex`) carry none by
    # construction, so a masked credential is unattributable to the masker no matter how long
    # it is. That is the measured cause of the 36 refusals, and the reason the armed rule is
    # the count.
    try:
        import content_mask as _cm
        agree = _cm.MARKER.encode() == SYNTHETIC_MARKER
        print()
        print("   %s  %-40s %s" % ("=", "the marker matches the masker's",
                                   "agrees" if agree else "DISAGREES"))
        if not agree:
            failures.append("SYNTHETIC_MARKER has drifted from content_mask.MARKER")
        bcrypt_in = b"$h = '$2y$10$" + b"a" * 53 + b"';"
        masked, _d = _cm.mask_sample(bcrypt_in, _cm.incident_mask.load_map(INCIDENT_MAP)
                                     if hasattr(_cm, "incident_mask") else None)
        moved = masked != bcrypt_in
        unmarked = SYNTHETIC_MARKER not in masked.lower()
        print("   %s  %-40s %s" % ("=", "a masked bcrypt carries no marker",
                                   "moved and unmarked" if (moved and unmarked)
                                   else ("unmoved" if not moved else "MARKED")))
        if not (moved and unmarked):
            failures.append("the premise of the count rule: a masked credential is "
                            "unattributable")
    except Exception as exc:                                    # noqa: BLE001
        print()
        print("   %s  %-40s %s" % ("=", "the marker matches the masker's",
                                   "NOT CHECKED: %s" % exc))
        failures.append("marker agreement could not be checked: %s" % exc)

    print()
    if failures:
        print("FAIL: the gate got %d of its own controls wrong: %s"
              % (len(failures), ", ".join(failures)))
        return 1
    print("every leak form is caught in the plaintext and inside every encoded layer, the "
          "secret gate sees a credential that survived its own masking, and the masked bytes "
          "on their own stay silent; the gate can fail")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="sample files to gate")
    ap.add_argument("--map", action="append", default=None,
                    help="pseudonym map, repeatable. Default is BOTH maps: a sample masked "
                         "against one can still carry a name from the other.")
    ap.add_argument("--inject", action="store_true",
                    help="prove the gate can fail, then exit")
    ap.add_argument("--inject-sample", default=None,
                    help="mask output to plant identifiers into, instead of a synthetic one")
    ap.add_argument("--before", default=None,
                    help="the pre-masking bytes of the single file being gated, so the "
                         "differential secret gate can run as well as the identifier gates")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--trials", type=int, default=60,
                    help="trials for --base-rate; the quoted figures are from 660")
    ap.add_argument("--stock-fp", action="store_true",
                    help="regenerate the false-positive table the findings cite: the same "
                         "predicate over stock CMS trees, which carry no customer of ours, "
                         "so every hit is a false positive")
    ap.add_argument("--stock-root", action="append",
                    default=[os.path.join("trail-data", "CMS"),
                             os.path.join("trail-data", "CMS-ext")])
    ap.add_argument("--base-rate", action="store_true",
                    help="re-run the null model the confidence grading rests on: random "
                         "base64 through the real predicate, so the figure in the grading "
                         "is reproducible rather than quoted")
    a = ap.parse_args()

    maps = a.map or [INCIDENT_MAP, LEGACY_MAP]
    ids, keep = load_ids(maps)
    print("maps                         : %s" % ", ".join(os.path.basename(m) for m in maps))
    print("client identifiers to look for: %d" % len(ids))

    if a.stock_fp:
        ids, keep = load_ids(a.map or [INCIDENT_MAP, LEGACY_MAP])
        r = stock_fp(ids, keep, a.stock_root, sample=a.trials if a.trials != 60 else 8000)
        print(json.dumps(r, indent=1))
        print()
        print("%d false positive(s) across %d of %d stock files (%.2f%%); "
              "%d from identifiers of %d+ characters"
              % (r["total_false_positives"], r["files_with_a_hit"], r["files_scanned"],
                 100.0 * r["files_with_a_hit"] / max(r["files_scanned"], 1),
                 sum(v for k, v in r["by_class"].items()
                     if int(k.split("=")[1].split()[0]) >= V.LONG_ENOUGH_TO_BE_ONLY_A_NAME),
                 V.LONG_ENOUGH_TO_BE_ONLY_A_NAME))
        return 0

    if a.base_rate:
        ids, keep = load_ids(a.map or [INCIDENT_MAP, LEGACY_MAP])
        r = base_rate(ids, keep, trials=a.trials)
        print(json.dumps(r, indent=1, sort_keys=True))
        print()
        print("short-name rule fired in %d of %d trials (%.1f%%); containment fired %d time(s)"
              % (r["trials_with_a_hit"], r["trials"],
                 100.0 * r["trials_with_a_hit"] / r["trials"], r["containment_hits"]))
        return 0

    if a.inject:
        print()
        return inject(ids, keep, a.inject_sample)

    if not a.files:
        print("no files given")
        return 2
    bad = 0
    out = []
    for p in a.files:
        raw = open(p, "rb").read()
        ok, res = gate(raw, ids, keep)
        if a.before:
            sok, sres = secret_gate(open(a.before, "rb").read(), raw)
            res.update(sres)
            ok = ok and sok
        res["file"] = os.path.basename(p)
        out.append(res)
        if not ok:
            bad += 1
        if not a.json:
            print("  %-8s %-8s %-8s layers=%-3d %s"
                  % (res["plaintext_gate"], res["encoded_layer_gate"],
                     res.get("secret_gate", "-"), res["layers_decoded"],
                     os.path.basename(p)))
    if a.json:
        print(json.dumps(out, indent=1, sort_keys=True))
    print()
    print("files gated                  : %d" % len(a.files))
    print("files failing a gate         : %d" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
