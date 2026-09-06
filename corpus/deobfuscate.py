#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The SECOND decoder, brought into the repository, and reconciled with the first.

THE PROBLEM THIS EXISTS FOR
---------------------------
`deobfuscation.decoded_form_tags` and its siblings sit on 142 local rows and were written by
`trail-data/incoming/2026-09-03/deobfuscate.py` - gitignored, untracked, 3,208 bytes. That
is the same condition `sensitivity.py` was in a round ago, one level down, and it is worse in
one specific way: this tree already HAS a decoder, `verify-content-mask.decode_layers`, and
the two do not agree about what a decoded layer is called or when one exists.

    recorded by the untracked one : base64, base64+inflate, hex-escape, octal-escape,
                                    hex-string, chr-sequence, rot13, and nested `a->b`
    emitted by the tracked one    : base64, base64+inflate, hex-string, escape,
                                    chr-sequence, raw-inflate, and nested `a->b`

Two vocabularies for one operation is how two artefacts that claim to be the same thing stop
being the same thing. `METHOD_ALIASES` states the correspondence, and `reconcile_methods()`
measures it on real bytes rather than asserting it: the names are only half of the
disagreement, and the thresholds are the other half.

    hex-escape + octal-escape  ->  escape        two recorder names, one tracked name. Both
                                                 recorder branches call `codecs.escape_decode`
                                                 on the same match class, so the merge loses
                                                 which escape form produced a layer, and a
                                                 row recording `hex-escape` cannot be
                                                 reproduced under the tracked name alone.
    rot13                      ->  (none)        the recorder has a branch the gate's decoder
                                                 does not. A `rot13` layer in the index is
                                                 one the gate has never seen.
    (none)                     <-  raw-inflate   and the reverse. The tracked decoder finds a
                                                 zlib/gzip stream anywhere in the bytes; the
                                                 recorder only inflates what base64 produced,
                                                 so every gzip container in the corpus is a
                                                 layer to one decoder and nothing to the other.

WHY THIS IS NOT IN gate_provenance.TOOLS, WHICH IS THE OPPOSITE OF THE OBVIOUS ANSWER
--------------------------------------------------------------------------------------
The argument FOR putting it in is strong and should be stated first: `sensitivity.py` was
kept out because "a tagger produces no gate verdict", and that reasoning does not transfer to
a decoder. The encoded-layer gate IS a decoder plus a predicate; `secret_gate` counts
literals over decoded layers; §5.4 exists because an identifier inside an encoded layer is
the thing that makes a sample unpublishable. A decoder is as load-bearing as a gate gets.

Measured, the premise is false FOR THIS MODULE, and the measurement is the argument:

    grep -n decode_layers corpus/*.py

    every call in the gate path resolves to `verify-content-mask.decode_layers`, which is
    ALREADY in TOOLS. Nothing in `corpus/` reads `deobfuscation` except
    `adopt-decoded-tags.py`, and that writes `sensitivity`, which is a publish BLOCKER and
    not a gate verdict.

`TOOLS` is not a list of important modules. It is the claim that changing a file changes a
stored `plaintext_gate`, `encoded_layer_gate`, `secret_gate` or `detection_survived`, and
this round has just paid that bill in public: repairing two credential shapes moved the
digest, invalidated 140 stamps, required 132 masked files to be regenerated from their
originals to recover them, cost 34 rows their `publishable` for the length of a commit, and
made a human clearance inert. Spending that on a module which cannot alter one of those four
verdicts would not make the corpus safer; it would make the digest the thing people route
around, which is how a check stops being a check.

And TOOLS would not address the real hazard anyway. It would say "the decoder changed"; it
would never say "the two decoders disagree", which is the actual defect and is what
`--reconcile` measures. So: its own digest, an explicit alias table, and a divergence check
that is run rather than assumed.

WHAT THIS MODULE IS
-------------------
A REPRODUCTION, not an improvement, for the reason `sensitivity.py` gives: a tracked module
whose behaviour differs from the one that ran cannot be used to review the rows it produced.
`--inject` asserts behavioural equality against the original over probes that carry no
customer identifier, and `--verify-reference` reports `ok` / `moved` / `absent` so a stranger
without the gitignored file gets *cannot check* rather than a quiet pass.

    corpus/deobfuscate.py <file>...            # layers, by method and length
    corpus/deobfuscate.py --reconcile <file>   # against verify-content-mask's decoder
    corpus/deobfuscate.py --digest
    corpus/deobfuscate.py --verify-reference
    corpus/deobfuscate.py --inject
"""
import ast, base64, binascii, codecs, collections, hashlib, importlib.util, json, os, re
import sys, zlib

HERE = os.path.dirname(os.path.abspath(__file__))

# The untracked original this module reproduces. A tool path is not a customer identifier;
# the file stays out of the repository because `trail-data` is gitignored wholesale.
REFERENCE = os.path.join("trail-data", "incoming", "2026-09-03", "deobfuscate.py")

# What the reference hashed to, by the same AST digest `gate_provenance` uses, when this
# reproduction was written and checked against it.
REFERENCE_DIGEST = "6de31d931ab1c677d4aba5a79e5c0a0ae212b1ec04fb639b12901a266be69de9"

# ---------------------------------------------------------------------------------------
# Reproduced verbatim from the reference. Every threshold below differs from the tracked
# decoder's and the differences are load-bearing, so they are NOT harmonised here: 142 rows
# were written by exactly these numbers.
#
#     this module          verify-content-mask
#     B64     {40,}        B64_RUN  {16,}
#     HEXSTR  quoted {40,} HEX_RUN  unquoted {24,}
#     CHRSEQ  {4,}         CHR_RUN  {6,}
#     texty   > 0.85       _texty   > 0.80
#     len(out) > 8         MIN_CARRY = 8   (>= rather than >)
#     max_depth 6          max_depth 4
# ---------------------------------------------------------------------------------------
B64 = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
HEXESC = re.compile(rb"(?:\\x[0-9A-Fa-f]{2}){4,}")
OCTESC = re.compile(rb"(?:\\[0-7]{1,3}){4,}")
CHRSEQ = re.compile(rb"(?:chr\(\s*\d{1,3}\s*\)\s*\.?\s*){4,}", re.I)
HEXSTR = re.compile(rb"['\"]([0-9A-Fa-f]{40,})['\"]")

# The vocabulary correspondence, stated once. `None` on either side is not a gap to fill in:
# it is a decoder that has a branch the other one does not, and a layer recorded under such a
# name cannot be reproduced by the other decoder at all.
METHOD_ALIASES = {
    "base64":         "base64",
    "base64+inflate": "base64+inflate",
    "hex-string":     "hex-string",
    "chr-sequence":   "chr-sequence",
    "hex-escape":     "escape",          # merged
    "octal-escape":   "escape",          # merged - two names collapse to one
    "rot13":          None,              # recorder only
}
TRACKED_ONLY = ("raw-inflate",)


def _texty(b):
    if not b:
        return False
    printable = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return printable / float(len(b)) > 0.85


def _try_inflate(b):
    for fn in (lambda x: zlib.decompress(x),
               lambda x: zlib.decompress(x, -15),
               lambda x: zlib.decompress(x, 16 + zlib.MAX_WBITS)):
        try:
            out = fn(b)
            if out:
                return out
        except Exception:
            pass
    return None


def decode_layers(data, depth=0, max_depth=6):
    """Return list of (method, decoded_bytes) for everything that decodes cleanly.

    Reproduced from the reference, including its lack of de-duplication: the tracked decoder
    keys a `seen` set on `hash(out)` and this one does not, so a file with two hundred base64
    runs that decode alike yields two hundred layers here and one there. That is one of the
    two reasons the layer COUNTS in the index do not match a re-derivation, and it is
    reproduced rather than fixed because 142 rows were counted this way.
    """
    if depth >= max_depth:
        return []
    found = []

    for m in B64.finditer(data):
        s = m.group(0)
        if len(s) < 40:
            continue
        try:
            raw = base64.b64decode(s + b"=" * (-len(s) % 4), validate=False)
        except Exception:
            continue
        if not raw:
            continue
        inf = _try_inflate(raw)
        if inf is not None and _texty(inf):
            found.append(("base64+inflate", inf))
        elif _texty(raw):
            found.append(("base64", raw))

    for m in HEXESC.finditer(data):
        try:
            out = codecs.escape_decode(m.group(0))[0]
            if _texty(out) and len(out) > 8:
                found.append(("hex-escape", out))
        except Exception:
            pass

    for m in OCTESC.finditer(data):
        try:
            out = codecs.escape_decode(m.group(0))[0]
            if _texty(out) and len(out) > 8:
                found.append(("octal-escape", out))
        except Exception:
            pass

    for m in HEXSTR.finditer(data):
        try:
            out = binascii.unhexlify(m.group(1))
            if _texty(out) and len(out) > 8:
                found.append(("hex-string", out))
        except Exception:
            pass

    for m in CHRSEQ.finditer(data):
        nums = re.findall(rb"\d{1,3}", m.group(0))
        try:
            out = bytes(bytearray(int(x) for x in nums if int(x) < 256))
            if _texty(out) and len(out) > 8:
                found.append(("chr-sequence", out))
        except Exception:
            pass

    try:
        rot = codecs.encode(data.decode("latin-1"), "rot_13").encode("latin-1")
        if b"<?php" in rot or b"eval(" in rot:
            found.append(("rot13", rot))
    except Exception:
        pass

    nested = []
    for meth, out in found[:24]:
        for m2, o2 in decode_layers(out, depth + 1, max_depth):
            nested.append((meth + "->" + m2, o2))
    return found + nested


# ---------------------------------------------------------------------------------------
# The reconciliation. A comparison, never a verdict, and it writes nothing.
# ---------------------------------------------------------------------------------------

def _tracked():
    spec = importlib.util.spec_from_file_location(
        "verify_content_mask_deob", os.path.join(HERE, "verify-content-mask.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_VCM = None


def vcm():
    global _VCM
    if _VCM is None:
        _VCM = _tracked()
    return _VCM


def _base(meth):
    """The outermost method of a nested name, which is what the alias table is keyed on."""
    return meth.split("->")[0]


def reconcile_methods(data):
    """What each decoder finds in these bytes, and how the two vocabularies line up.

    Four classes per method, and the fourth exists so a name nobody anticipated cannot be
    silent - the discipline `shard-gate.gate_result` uses for the same reason:

      same        - the recorder's name maps to a tracked name and both decoders produced it
      merged      - two recorder names collapse into one tracked name
      recorder-only / tracked-only - a branch one decoder has and the other does not
    """
    mine = decode_layers(data)
    theirs = vcm().decode_layers(data)
    my_names = collections.Counter(_base(m) for m, _b in mine)
    their_names = collections.Counter(_base(m) for m, _b in theirs)

    rows = []
    for name in sorted(set(my_names) | set(their_names)):
        if name in METHOD_ALIASES:
            alias = METHOD_ALIASES[name]
            if alias is None:
                cls = "recorder-only"
            elif sum(1 for k, v in METHOD_ALIASES.items() if v == alias) > 1:
                cls = "merged"
            else:
                cls = "same"
            rows.append({"name": name, "side": "recorder", "class": cls,
                         "tracked_name": alias, "count": my_names.get(name, 0),
                         "tracked_count": their_names.get(alias, 0) if alias else 0})
        elif name in TRACKED_ONLY or name not in METHOD_ALIASES:
            rows.append({"name": name, "side": "tracked", "class": "tracked-only",
                         "tracked_name": name, "count": 0,
                         "tracked_count": their_names.get(name, 0)})
    # De-duplicate: a tracked name that is an alias target has already been reported beside
    # the recorder name that maps to it.
    targets = {v for v in METHOD_ALIASES.values() if v}
    rows = [r for r in rows if not (r["side"] == "tracked" and r["name"] in targets)]
    return {"recorder_layers": len(mine), "tracked_layers": len(theirs),
            "recorder_methods": dict(my_names), "tracked_methods": dict(their_names),
            "methods": rows}


# ---------------------------------------------------------------------------------------
# Provenance for a decoding claim.
# ---------------------------------------------------------------------------------------

def _strip_docstrings(tree):
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
            continue
        body = getattr(node, "body", None)
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            node.body = body[1:] or [ast.Pass()]
    return tree


def _ast_digest(path):
    with open(path, encoding="utf-8") as fh:
        tree = _strip_docstrings(ast.parse(fh.read()))
    return hashlib.sha256(ast.dump(tree).encode("utf-8")).hexdigest()


def digest():
    """This module's behavioural digest, on `gate_provenance`'s terms and separate from it."""
    return _ast_digest(os.path.abspath(__file__))[:12]


def reference_digest(path=None):
    """(state, digest). 'ok', 'moved' or 'absent' - three answers, never two."""
    p = path or os.path.join(os.path.dirname(HERE), REFERENCE)
    if not os.path.exists(p):
        return "absent", None
    d = _ast_digest(p)
    return ("ok" if d == REFERENCE_DIGEST else "moved"), d


# ---------------------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------------------

# No customer identifier appears below. Every path, host and credential is synthetic.
PROBES = [
    ("plain php, nothing to decode", b"<?php echo 1; ?>"),
    ("a base64 run under the 40-char floor",
     b"$x='" + base64.b64encode(b"/home/acct01/x") + b"';"),
    ("a base64 run over it",
     b"$x='" + base64.b64encode(b"/home/acct01/public_html/index.php and more text") + b"';"),
    ("base64 over a deflate stream",
     b"$x='" + base64.b64encode(zlib.compress(b"<?php eval($_POST['q']); // " + b"a" * 80))
     + b"';"),
    ("a hex escape run", b"$x=\"\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x61\\x63\\x63\\x74\\x30\\x31"
                         b"\\x2f\\x70\\x75\\x62\\x6c\\x69\\x63\";"),
    ("an octal escape run", b"$x=\"\\57\\150\\157\\155\\145\\57\\141\\143\\143\\164\\60\\61"
                            b"\\57\\160\\165\\142\";"),
    ("a quoted hex string",
     b"$x='" + binascii.hexlify(b"/home/acct01/public_html/i.php") + b"';"),
    ("a chr() sequence",
     b"$x=" + b".".join(b"chr(%d)" % c for c in b"/home/acct01/pub") + b";"),
    ("rot13 over php", codecs.encode("<?php eval($_POST['q']);", "rot_13").encode()),
    ("a raw gzip stream, which only the tracked decoder names",
     zlib.compress(b"<?php // an ordinary file " + b"b" * 200)),
    ("nested: base64 inside base64",
     b"$x='" + base64.b64encode(b"$y='" + base64.b64encode(
         b"/home/acct01/public_html/deep.php and padding text") + b"';") + b"';"),
]


def inject():
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-64s %-22s %s" % (label, str(got)[:22],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    print("1. the reproduction against the untracked original")
    state, d = reference_digest()
    if state == "absent":
        print("   ~ reference not on this machine: %s" % REFERENCE)
        print("     cannot check; reported as 'absent' rather than passing quietly")
    else:
        case("reference digest matches what this was written against", state, "ok")
        if state == "moved":
            print("     reference now hashes to %s, recorded %s" % (d, REFERENCE_DIGEST))
    refpath = os.path.join(os.path.dirname(HERE), REFERENCE)
    if os.path.exists(refpath):
        spec = importlib.util.spec_from_file_location("deobfuscate_reference", refpath)
        ref = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ref)
        same = all(ref.decode_layers(b) == decode_layers(b) for _l, b in PROBES)
        case("behaviour equals the reference over %d probes" % len(PROBES), same, True)
        # The negative half. A reproduction that returned [] for everything would satisfy
        # the line above, so at least one probe has to produce something.
        case("and the probes are not all empty",
             sum(len(decode_layers(b)) for _l, b in PROBES) > 0, True)
    else:
        print("   ~ the reference is not importable here; behavioural equality NOT checked")

    print()
    print("2. every method in the vocabulary is reachable from the probes")
    seen = set()
    for _l, b in PROBES:
        seen |= {_base(m) for m, _x in decode_layers(b)}
    for name in ("base64", "base64+inflate", "hex-escape", "octal-escape", "hex-string",
                 "chr-sequence", "rot13"):
        case("this decoder can still produce %s" % name, name in seen, True)
    tracked_seen = set()
    for _l, b in PROBES:
        tracked_seen |= {_base(m) for m, _x in vcm().decode_layers(b)}
    for name in TRACKED_ONLY:
        case("the tracked decoder can still produce %s" % name, name in tracked_seen, True)

    print()
    print("3. the two vocabularies, and the ways they fail to line up")
    case("every recorder method has an entry in METHOD_ALIASES",
         sorted(seen - set(METHOD_ALIASES)), [])
    case("hex-escape and octal-escape collapse to one tracked name",
         METHOD_ALIASES["hex-escape"] == METHOD_ALIASES["octal-escape"] == "escape", True)
    case("rot13 has no tracked equivalent", METHOD_ALIASES["rot13"], None)
    r = reconcile_methods(PROBES[4][1])                     # the hex-escape probe
    row = next((x for x in r["methods"] if x["name"] == "hex-escape"), None)
    case("a hex-escape layer is reported as merged", row and row["class"], "merged")
    case("and the tracked decoder finds it under `escape`",
         row and row["tracked_count"] > 0, True)
    r2 = reconcile_methods(PROBES[9][1])                    # the raw gzip probe
    case("a raw gzip stream is recorder-INVISIBLE",
         [x for x in r2["methods"] if x["name"] == "raw-inflate"][0]["count"], 0)
    case("and tracked-only", [x for x in r2["methods"]
                              if x["name"] == "raw-inflate"][0]["class"], "tracked-only")
    r3 = reconcile_methods(PROBES[8][1])                    # rot13
    case("rot13 is recorder-only",
         [x for x in r3["methods"] if x["name"] == "rot13"][0]["class"], "recorder-only")

    print()
    print("4. the thresholds differ, and that is a behavioural difference not a naming one")
    short = PROBES[1][1]
    case("a base64 run under this decoder's 40-char floor yields nothing here",
         len(decode_layers(short)), 0)
    case("and the tracked decoder, whose floor is 16, does find it",
         len(vcm().decode_layers(short)) > 0, True)

    print()
    print("5. its digest is its own, and not the gate's")
    sys.path.insert(0, HERE)
    import gate_provenance
    case("deobfuscate.py is not in gate_provenance.TOOLS",
         "deobfuscate.py" in gate_provenance.TOOLS, False)
    case("its digest is 12 hex characters",
         len(digest()) == 12 and all(c in "0123456789abcdef" for c in digest()), True)
    # The argument in the docstring, asserted: nothing in the gate path calls this module.
    gate_src = open(os.path.join(HERE, "verify-content-mask.py"), encoding="utf-8").read()
    case("the gate does not import this module", "deobfuscate" in gate_src, False)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*")
    ap.add_argument("--reconcile", action="store_true",
                    help="compare against verify-content-mask.decode_layers")
    ap.add_argument("--digest", action="store_true")
    ap.add_argument("--verify-reference", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()

    if a.inject:
        return inject()
    if a.digest:
        print("decoder digest      : %s" % digest())
        state, d = reference_digest()
        print("untracked reference : %s%s" % (state, " (%s)" % d[:12] if d else ""))
        return 0
    if a.verify_reference:
        state, d = reference_digest()
        print("reference: %s" % REFERENCE)
        print("state    : %s" % state)
        if d:
            print("digest   : %s (recorded %s)" % (d, REFERENCE_DIGEST))
        if state == "absent":
            print("\nThe original is gitignored and out of repo, so this is the normal "
                  "answer\nfor anyone but the collector. It is reported rather than passed.")
        return 0 if state in ("ok", "absent") else 1
    if not a.files:
        return ap.error("give some files, or --reconcile / --digest / --inject")

    out = {}
    for p in a.files:
        with open(p, "rb") as fh:
            data = fh.read()
        rec = {"layers": collections.Counter(_base(m) for m, _b in decode_layers(data))}
        if a.reconcile:
            rec["reconcile"] = reconcile_methods(data)
        out[os.path.basename(p)] = rec
    # Method names and counts only. §5.3's seventh failure was a gate result whose contents
    # were the identifiers it had just found.
    print(json.dumps(out, indent=1, sort_keys=True, default=dict))
    return 0


if __name__ == "__main__":
    sys.exit(main())
