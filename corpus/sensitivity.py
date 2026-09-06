#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§4.1 axis B - the sensitivity tagger, brought into the repository.

THE PROBLEM THIS EXISTS FOR
---------------------------
Every mechanically-derived `sensitivity` tag in the index was written by
`trail-data/incoming/2026-09-03/sensitivity.py`, which is **not tracked**: it is gitignored
under `trail-data`, and `gate_provenance.TOOLS` does not cover it. A stranger who clones
this repository can read the rows and cannot read the rule that made them. They cannot
re-run it, cannot review it, and cannot tell whether it has changed since the rows were
written. That is the same condition as a `not_applicable_reason` written by an uncommitted
tool, one level up and on a field that decides publishability: `pii` and `content` are
`shard-gate.NEVER`, and `clean` is what lets a row ship as-is.

**It was never only the `secret` tag.** `classify()` returns one set covering `content`,
`path`, `identity`, `secret`, `c2`, `pii` and `clean`, and every caller takes the whole set
(`r["sensitivity"] = tags`); not one of them selects a single tag. Measured over both index
halves: `secret` is 92 rows, but the tags this rule can emit are 45,242 `clean`, 4,277
`content`, 788 `c2`, 287 `identity`, 178 `pii` and 46 `path`. Only `unreviewed` and
`undecidable` are outside its vocabulary. 235 rows carry a `sensitivity_evidence` block
whose keys and values are this function's `ev` dict verbatim - `customer_hosts`/`emails`/
`ips`, `external_hosts`/`markers`, and the `SECRET_PATTERNS` names `literal-password`,
`wp-db-password`, `wp-db-user`, `wp-salt`, `bcrypt-hash`, `private-key`, `phpass-hash` -
which is what attributes them to this rule rather than to a convention.

WHAT THIS MODULE IS, AND WHAT IT DELIBERATELY IS NOT
----------------------------------------------------
It **reproduces** the untracked rule rather than improving it. That ordering is the point:
a tracked module whose behaviour differs from the one that ran cannot be used to review the
rows that ran through it, which is the whole reason for tracking it. `--verify-reference`
asserts the reproduction against the original where the original is present, and says so
rather than passing quietly where it is not.

Two things are therefore NOT changed here, both measured and both reported instead:

  * **`identity` fires on any e-mail or any IP.** `if cust_hosts or emails or ips`. On a
    5 MB plugin tarball that is 81 upstream contributor addresses across 44 domains, none of
    them on a customer domain - an `identity` tag with no customer in it.
  * **`c2` fires on any external host.** "an external host referenced from a malicious
    sample is attacker infrastructure" holds for a webshell and not for a database dump of a
    real site: 20 of 73 external hosts in that same tarball are php.net, wordpress.org,
    github.com, MDN and two CDNs, and 8 of 28 in a WordPress dump are wordpress.org, w3.org
    and youtube.com. `c2` is in `shard-gate.ALWAYS_OK`, so a wrong `c2` tag is a tag that
    never blocks.

Changing either moves tag counts on rows nobody has re-read. They are findings for a human
to rule on, not repairs to slip into a reproduction. **CORPUS_PLAN §4.1 now carries the rule
those humans rule by:** `c2` requires evidence of attacker control and never the presence of
an external host, because the tag is in `ALWAYS_OK` and buys a masking exemption rather than
merely labelling a sample. So this function's `external-host` branch produces a PROPOSAL, and
`tag-sensitivity.py` requires every proposal to be added, rejected or held by a person.

WHAT THE RULE CANNOT SEE, WHICH IS THE FINDING
-----------------------------------------------
`classify()` reads the bytes it is handed and has **no decoder**. §5.4 states the principle
it violates - "the absence of a plaintext hit is evidence the encoder worked, not evidence
the sample is clean" - and `verify-content-mask.py` exists because of it. The tagger never
got the lesson, and `clean` is the DEFAULT BRANCH of a function with no decoder: `if not
tags: tags.add("clean")`. Every way of failing to read a sample arrives at the tag that
means "publish as-is".

Measured on the five local rows that are `publishable: true` with zero blockers, tagged
`clean` alone, and carry no masking record. All five are `clean` for exactly this reason -
four are gzip streams and the fifth hides its payload in a base64 literal, so every regex
above sees compressed noise:

    row            raw-byte tags   tags over the same bytes decoded
    1438674b06d8   clean           c2, identity, pii
    c24465d301e2   clean           c2, identity, pii
    cd98180175a5   clean           path
    e50d85a3a815   clean           c2, identity, path, pii, secret
    eba16e1e9159   clean           c2, identity

So `layers` is an explicit argument here rather than an internal decision, and
`classify_deep()` is the form that uses it. The decoder is `verify-content-mask.decode_layers`
- the gate's own, not a second one - so that a tag and a gate that disagree are disagreeing
about a rule and never about which bytes they read. Which form produced a tag is recorded in
`ev["_read"]`, because "clean over the wrapper" and "clean over everything it decodes to"
are different claims and the index has been storing them as one word.

THE TAGGER AND THE GATE MAY LEGITIMATELY DIFFER, AND THE BOUNDARY IS NOT LENGTH
-------------------------------------------------------------------------------
`SECRET_PATTERNS` here and `verify-content-mask.SECRET_SHAPES` are two definitions of a
credential in one tree, and they answer different questions:

  * the TAGGER asks *is a credential present*. It is a claim about the row, and it decides
    whether a masking pass is owed. A false positive costs one unnecessary masking pass; a
    false negative publishes a credential. It should over-match.
  * the GATE asks *did masking change every credential-shaped literal*. It is a differential
    over VALUES. It needs a value it can capture and compare; a pattern that matches a bare
    constant name has nothing on either side of the difference.

That is the legitimate difference, and it is a property of the pattern rather than of the
rule: **a shape with no capturable value can only be tagged, never gated.** `SHAPE_KIND`
below records which is which, so the distinction is a fact about each pattern rather than a
judgement made per row.

The tagger is authoritative for TAGGING and the gate is authoritative for GATING, and
neither may be quietly narrower than the other where both can see a value. Two ways it was,
both measured, **both repaired in `verify-content-mask.py` and recorded here because the
measurement is what justified the repair**:

  1. **The gate had no PEM shape at all.** `-----BEGIN … PRIVATE KEY-----` was tagged and
     invisible to `SECRET_SHAPES`. A PEM block has a value - its base64 body - so it is
     gateable and the gate simply did not look. `pem-private-key` now exists and requires a
     COMPLETE block, opening marker through closing marker: on the two rows this was written
     for there are 34 `BEGIN` markers and **zero** `END` markers, 32 of them inside docblock
     prose in a vendor crypto library that a scan report quotes. A header-only shape would
     have failed both rows on documentation.
  2. **The gate's left lookbehind was stricter than the tagger's.** `quoted-credential`
     opened `(?<![A-Za-z0-9_])`; the tagger's `literal-password` has no left boundary. A
     password assigned to a variable whose name ENDS with the keyword was tagged and not
     gated: `$user_password = '…'`, `$adminpassword = '…'`, and `$pwd = '…'` (the gate had
     no `pwd` at all). §5.6 already says lookarounds in an identifier regex should err
     towards over-matching, and records two leaks caused by a lookaround that was too
     strict; this was the third, on credentials rather than identifiers. The lookbehind is
     gone and `pwd` is in the keyword list.

THE VACUOUS PASS IS A CONSEQUENCE, NOT A RULE
----------------------------------------------
Nine rows carry the `secret` tag and record `secret_gate: PASS` over zero credential-shaped
literals on both sides; one of them is `publishable: true`. Once the two definitions are
stated together the nine decompose into two causes with different repairs, which is what
§8 asks of a count:

  * **five are name-only** - `wp-salt` ×4, `wp-db-password`+`wp-db-user` ×1. The bytes carry
    a bare constant name and no quoted value. Nothing exists to compare, the gate's zero is
    correct, and the defect is only that `PASS` is the wrong word for a measurement that had
    no subject.
  * **two are a real divergence** - `literal-password` ×2 (cause 2). On the publishable one
    the character before the keyword is `_`; on the other it is a letter. Both are
    credentials in the bytes the gate could not see, and one of them is in a `base64` layer
    on a row that ships. The repaired gate returns FAIL on both.
  * **and two are not a divergence at all**, which is the correction rather than the count.
    The `private-key` ×2 were read as "two PEM blocks the gate has no shape for". Measured:
    34 `BEGIN … PRIVATE KEY` markers per row, **0 `END` markers**, 32 of them inside docblock
    prose. There is no key body on either row, so there is no value for any gate to compare
    and the class is `name-only` in fact even though `SHAPE_KIND` calls the PATTERN
    value-bearing. `reconcile()` classifies by pattern, as documented, so it still answers
    `gate-cannot-see` on a bare header; what changed is that the finding behind those two
    rows is now known to be documentation, and the repaired gate correctly stays silent on
    it. The nine therefore decompose 5 / 2 / 2, not 5 / 4.

`reconcile()` returns that decomposition per row. It is a comparison and writes nothing.

WHY THIS IS NOT IN gate_provenance.TOOLS
-----------------------------------------
`TOOLS` is "the modules whose logic decides a stored GATE VERDICT", and `shard-gate.py` is
deliberately absent from it because it consumes verdicts and does not produce them. This
module produces no gate verdict either: it produces the `sensitivity` field. Adding it would
put all 140 stamped rows into re-measurement every time a tagging rule moved, for a change
that cannot alter a single `plaintext_gate`, `encoded_layer_gate`, `secret_gate` or
`detection_survived` result - the same coupling the AST digest exists to avoid, pointed the
other way. Measured: `gate_provenance.tools_digest()` is `6fecbeebbccc` on 140 rows before
this commit and is unchanged by it, and `--assert-digest-unmoved` is the control.

The answer is not to widen `TOOLS`, it is that a sensitivity claim has no provenance at all.
`digest()` gives it one on the same terms - an AST digest, docstrings stripped, so prose does
not move it - and `reference_digest()` records what the untracked original hashed to when
this reproduction was written, so a stranger with only the repository can see whether the
rule they can read is the rule that ran.
"""
import ast, hashlib, importlib.util, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))

# The untracked original this module reproduces. Named by path because a tool path is not a
# customer identifier; the file itself stays out of the repository because it lives under
# `trail-data`, which is gitignored wholesale and must stay that way.
REFERENCE = os.path.join("trail-data", "incoming", "2026-09-03", "sensitivity.py")

# What the reference hashed to when this reproduction was written and checked against it, by
# the same AST digest `gate_provenance` uses. A stranger cannot run `--verify-reference`
# because the file is out of repo; this is what they can compare against if it ever arrives.
REFERENCE_DIGEST = "28c231163fdd47abd53536979f19a62410328f37bb4d74609a7579e9813fb68f"

# Reproduced verbatim from the reference. Order is preserved because `ev["secret"]` is a
# sorted set of these names and 235 rows already carry them.
SECRET_PATTERNS = [
    (rb"DB_PASSWORD", "wp-db-password"),
    (rb"DB_USER", "wp-db-user"),
    (rb"AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|NONCE_SALT", "wp-salt"),
    (rb"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", "bcrypt-hash"),
    (rb"\$P\$[./A-Za-z0-9]{31}", "phpass-hash"),
    (rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private-key"),
    (rb"(?i)api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}", "api-key"),
    (rb"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "literal-password"),
    (rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.", "jwt"),
    (rb"(?i)aws_secret_access_key", "aws-secret"),
    (rb"(?i)smtp_pass|mail_password", "smtp-password"),
]

# Which of those a differential gate can act on. This is a property of the PATTERN - does
# matching it yield a value to compare - and not a judgement about the row, which is why it
# is a table here rather than a branch in `reconcile()`.
#
#   value-bearing : the match contains a credential VALUE. Both sides can see it, so a tag
#                   without a corresponding gate literal is a divergence to explain.
#   name-only     : the match is a constant name, an assignment keyword or a header. There is
#                   no value on either side of a difference, so a gate reporting zero is
#                   correct and says nothing about whether a credential is present.
SHAPE_KIND = {
    "wp-db-password": "name-only",
    "wp-db-user":     "name-only",
    "wp-salt":        "name-only",
    "aws-secret":     "name-only",
    "smtp-password":  "name-only",
    "bcrypt-hash":    "value-bearing",
    "phpass-hash":    "value-bearing",
    "private-key":    "value-bearing",
    "api-key":        "value-bearing",
    "literal-password": "value-bearing",
    "jwt":            "value-bearing",
}

# Attacker infrastructure markers - kept deliberately (§4.1)
C2_HINTS = [
    (rb"(?i)t\.me/|api\.telegram\.org|bot\d{6,}:[A-Za-z0-9_-]{30,}", "telegram"),
    (rb"(?i)gsocket\.io|gs-netcat", "gsocket"),
    (rb"(?i)pastebin\.com/raw|raw\.githubusercontent\.com|gist\.github", "raw-paste-host"),
    (rb"(?i)\.onion(?![A-Za-z0-9])", "tor"),
    (rb"(?i)ngrok\.io|serveo\.net|localtunnel", "tunnel"),
]

PII_HINTS = [
    (rb"(?i)\b(first_?name|last_?name|billing_address|phone|telephone|postcode|zip_?code)\b",
     "form-field"),
    (rb"(?i)\border_?(id|number|total)\b", "order-record"),
    (rb"(?i)\b(iban|vat_?number|tax_?id|credit_?card|cc_?number)\b", "financial"),
]

EMAIL = re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")
IPV4 = re.compile(rb"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
URL = re.compile(rb"https?://([A-Za-z0-9.\-]{3,255})")

# Every tag this rule can emit. `unreviewed` and `undecidable` are NOT here: nothing
# mechanical assigns them, which is why they are the two tags in the index outside this
# vocabulary.
TAGS = frozenset({"content", "path", "identity", "secret", "c2", "pii", "clean"})


def build(mapping, dommap):
    """The compiled identifier context. Interface preserved from the reference."""
    accts = sorted(mapping, key=len, reverse=True)
    return {
        "acct_re": re.compile(r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])" %
                              "|".join(re.escape(a) for a in accts if len(a) >= 3)),
        "home_re": re.compile(rb"/home/([A-Za-z0-9_.-]{2,32})/"),
        "dom_re": re.compile("|".join(re.escape(d) for d in
                                      sorted(dommap, key=len, reverse=True)), re.I)
        if dommap else None,
    }


def classify(data, ctx, customer_domains, is_media=False):
    """Reproduction of the reference. (tags, evidence) over ONE blob, no decoding.

    Never returns 'clean' together with another tag. Kept identical so a row written by the
    reference can be re-derived exactly; `classify_deep` is the form that decodes.
    """
    tags = set()
    ev = {}
    if is_media:
        tags.add("content")

    m = ctx["home_re"].findall(data)
    if m:
        tags.add("path")
        ev["path"] = sorted({x.decode("ascii", "replace") for x in m})[:8]

    hosts = set()
    for h in URL.findall(data):
        hosts.add(h.decode("ascii", "replace").lower())
    emails = {e.decode("ascii", "replace") for e in EMAIL.findall(data)}
    ips = {i.decode("ascii", "replace") for i in IPV4.findall(data)}

    cust_hosts = {h for h in hosts if any(d in h for d in customer_domains)}
    ext_hosts = hosts - cust_hosts
    if cust_hosts or emails or ips:
        tags.add("identity")
        ev["identity"] = {"customer_hosts": sorted(cust_hosts)[:6],
                          "emails": sorted(emails)[:6], "ips": sorted(ips)[:6]}

    sec = []
    for pat, name in SECRET_PATTERNS:
        if re.search(pat, data):
            sec.append(name)
    if sec:
        tags.add("secret")
        ev["secret"] = sorted(set(sec))

    c2 = []
    for pat, name in C2_HINTS:
        if re.search(pat, data):
            c2.append(name)
    # an external host referenced from a malicious sample is attacker infrastructure
    if ext_hosts:
        c2.append("external-host")
        ev.setdefault("c2", {})["external_hosts"] = sorted(ext_hosts)[:8]
    if c2:
        tags.add("c2")
        ev.setdefault("c2", {})["markers"] = sorted(set(c2))

    pii = []
    for pat, name in PII_HINTS:
        if re.search(pat, data):
            pii.append(name)
    if pii:
        tags.add("pii")
        ev["pii"] = sorted(set(pii))

    if not tags:
        tags.add("clean")
    return sorted(tags), ev


def _decoder():
    """`verify-content-mask.decode_layers`, loaded rather than restated.

    The gate's decoder and not a second one: a tag and a gate that disagree must be
    disagreeing about a rule, never about which bytes each of them read.
    """
    spec = importlib.util.spec_from_file_location(
        "verify_content_mask", os.path.join(HERE, "verify-content-mask.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_VCM = None


def vcm():
    global _VCM
    if _VCM is None:
        _VCM = _decoder()
    return _VCM


def classify_deep(data, ctx, customer_domains, is_media=False, layers=None):
    """(tags, evidence) over the bytes AND every layer they statically decode to.

    The repair for the failure in the module docstring. `ev["_read"]` records which form
    produced what, because `clean` over a gzip wrapper and `clean` over everything inside it
    are different claims and the index stores them as the same word.

    Returns the UNION of the tags, with `clean` present only when nothing else is - the
    reference's own invariant, applied to the wider read.
    """
    if layers is None:
        layers = vcm().decode_layers(data)

    raw_tags, ev = classify(data, ctx, customer_domains, is_media)
    tags = set(raw_tags) - {"clean"}
    from_layers = {}
    for meth, out in layers:
        t, e = classify(out, ctx, customer_domains, False)
        t = set(t) - {"clean"}
        if not t:
            continue
        tags |= t
        for tag in sorted(t):
            from_layers.setdefault(tag, []).append(meth)
        for k, v in e.items():
            ev.setdefault(k, v)

    ev["_read"] = {
        "raw_tags": sorted(set(raw_tags)),
        "layers_decoded": len(layers),
        "layer_methods": sorted({m for m, _ in layers}),
        "tags_only_in_layers": sorted(tags - (set(raw_tags) - {"clean"})),
        "which_layer_first_showed_each": {k: sorted(set(v))[:4]
                                          for k, v in sorted(from_layers.items())},
    }
    if not tags:
        tags.add("clean")
    return sorted(tags), ev


# ---------------------------------------------------------------------------------------
# Reconciliation with the gate's credential definition.
# ---------------------------------------------------------------------------------------

def tagger_secret_shapes(data, layers=None):
    """The secret shape names this rule finds in the bytes and in each decoded layer."""
    blobs = [data] + [b for _m, b in (layers if layers is not None
                                      else vcm().decode_layers(data))]
    found = set()
    for blob in blobs:
        for pat, name in SECRET_PATTERNS:
            if re.search(pat, blob):
                found.add(name)
    return found


def reconcile(data, layers=None):
    """Why the tagger and the gate disagree about credentials in these bytes.

    Returns a record, never a verdict, and writes nothing. Four causes, and the fourth
    exists so a combination nobody anticipated cannot be silent - the four-class discipline
    `shard-gate.gate_result` uses for the same reason.

      agree                  - both see a value, or neither sees anything
      name-only              - the tagger matched a constant name with no value in the bytes.
                               The gate's zero is correct and measures nothing.
      gate-cannot-see        - the tagger matched a VALUE-bearing shape and the gate found no
                               literal. A credential the gate is blind to.
      tagger-cannot-see      - the gate found a literal the tagger did not tag. The mirror,
                               asked because a check that can only fail one way is the defect
                               this corpus keeps finding.
    """
    if layers is None:
        layers = vcm().decode_layers(data)
    tagged = tagger_secret_shapes(data, layers)
    literals = vcm().secret_literals(data, layers=layers)
    gate_shapes = {s for s, _v in literals}

    value_bearing = {n for n in tagged if SHAPE_KIND.get(n) == "value-bearing"}
    name_only = {n for n in tagged if SHAPE_KIND.get(n) == "name-only"}

    if value_bearing and not gate_shapes:
        cause = "gate-cannot-see"
    elif gate_shapes and not tagged:
        cause = "tagger-cannot-see"
    elif name_only and not value_bearing and not gate_shapes:
        cause = "name-only"
    else:
        cause = "agree"
    return {"cause": cause,
            "tagger_shapes": sorted(tagged),
            "tagger_value_bearing": sorted(value_bearing),
            "tagger_name_only": sorted(name_only),
            "gate_shapes": sorted(gate_shapes),
            "gate_literal_count": len(literals),
            "layers_decoded": len(layers)}


# ---------------------------------------------------------------------------------------
# Provenance for a sensitivity claim.
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
    """This module's behavioural digest, on `gate_provenance`'s terms.

    Deliberately its own and not part of `gate_provenance.tools_digest()`: see the module
    docstring. A `sensitivity` claim can carry this the way a masking verdict carries a
    `tools` stamp, and moving a tagging rule then re-measures tagging and nothing else.
    """
    return _ast_digest(os.path.abspath(__file__))[:12]


def reference_digest(path=None):
    """(state, digest) for the untracked original. Three answers, never two.

    'ok'      - present and equal to what this reproduction was written against
    'moved'   - present and different: the rule that produced the rows is not this one
    'absent'  - not on this machine, which is the normal case for anyone but the collector
    """
    p = path or os.path.join(os.path.dirname(HERE), REFERENCE)
    if not os.path.exists(p):
        return "absent", None
    d = _ast_digest(p)
    return ("ok" if d == REFERENCE_DIGEST else "moved"), d


# ---------------------------------------------------------------------------------------
# Controls. AGENTS.md: a check that has never been observed to fail is not yet a check, and
# the control ships in the same commit as the check.
# ---------------------------------------------------------------------------------------

# Probes carry NO customer identifier. Every account name, domain and credential below is
# synthetic - `demo24.tld` and `acctNN` are the pseudonym forms the gate already asserts.
PROBES = [
    ("bare clean php", b"<?php echo 1; ?>"),
    ("home path", b"require '/home/acct07/public_html/x.php';"),
    ("customer host in a url", b"<a href='https://demo24.tld/a'>x</a>"),
    ("an email alone", b"contact: nobody@example.org"),
    ("an ipv4 alone", b"connect 203.0.113.9"),
    ("external host only", b"fetch https://cdn.example.net/a.js"),
    ("telegram c2", b"https://api.telegram.org/bot123456:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/x"),
    ("wp salt name only", b"define('AUTH_KEY', PLACEHOLDER_CONST);"),
    ("wp salt with a value", b"define('AUTH_KEY', 'zzzzzzzzzzzzzzzz');"),
    ("literal password, bare", b"$password = 'hunter2xx';"),
    ("literal password, prefixed name", b"$user_password = 'hunter2xx';"),
    ("literal password, glued name", b"$adminpassword='hunter2xx';"),
    ("pwd keyword", b"$pwd = 'hunter2xx';"),
    ("pem private key", b"-----BEGIN RSA PRIVATE KEY-----\nQUFB\n-----END RSA PRIVATE KEY-----"),
    ("phpass hash", b"$P$Baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ("pii form field", b"<input name='telephone'>"),
]


def _probe_ctx():
    return build({"acct07": "acct07"}, {"demo24.tld": "demo24.tld"}), {"demo24.tld"}


def inject():
    """Positive control: prove every claim this module makes can also say the other thing.

    Five assertions, each of which has a way to fail:

      1. the reproduction equals the reference where the reference is present, and says
         'absent' rather than passing where it is not;
      2. `classify` emits every tag in `TAGS` over the probe set - a rule that could no
         longer produce a tag would be silent otherwise;
      3. `classify_deep` sees a tag through an encoded layer that `classify` misses. This is
         the whole repair, and a decoder that stopped working would leave it green without
         it;
      4. `SHAPE_KIND` covers every name in `SECRET_PATTERNS`, so a new pattern cannot join
         without a decision about whether a gate can act on it;
      5. `reconcile` returns each of its causes on an input built to produce it, INCLUDING
         `gate-cannot-see` on the two forms measured in the index.
    """
    failures = []

    def case(label, got, want):
        ok = got == want
        print("   %s %-58s %s" % ("+" if ok else "!", label,
                                  "%r" % (got,) if ok else "%r, wanted %r" % (got, want)))
        if not ok:
            failures.append(label)

    ctx, cust = _probe_ctx()

    print("1. the reproduction against the untracked original")
    state, d = reference_digest()
    if state == "absent":
        print("   ~ reference not on this machine: %s" % REFERENCE)
        print("     cannot check; reported as 'absent' rather than passing quietly")
    else:
        case("reference digest matches what this was written against", state, "ok")
        if state == "moved":
            print("     reference now hashes to %s, recorded %s" % (d, REFERENCE_DIGEST))
    # behavioural equality, which is the claim that actually matters
    if os.path.exists(os.path.join(os.path.dirname(HERE), REFERENCE)):
        sys.path.insert(0, os.path.dirname(os.path.join(os.path.dirname(HERE), REFERENCE)))
        try:
            import sensitivity as _ref          # the untracked one, by directory precedence
            if os.path.abspath(_ref.__file__) != os.path.abspath(__file__):
                same = all(_ref.classify(b, _ref.build({"acct07": "acct07"},
                                                       {"demo24.tld": "demo24.tld"}), cust)[0]
                           == classify(b, ctx, cust)[0] for _l, b in PROBES)
                case("behaviour equals the reference over %d probes" % len(PROBES),
                     same, True)
        except Exception as exc:                                    # pragma: no cover
            print("   ~ could not import the reference for comparison: %s" % exc)

    print("2. every tag in the vocabulary is reachable")
    seen = set()
    for _l, b in PROBES:
        seen |= set(classify(b, ctx, cust)[0])
    seen |= set(classify(b"\x89PNG", ctx, cust, is_media=True)[0])
    case("tags produced over the probe set", sorted(seen), sorted(TAGS))

    print("3. the decoder is what makes an encoded tag visible")
    import base64
    inner = b"$user_password = 'hunter2xx'; // https://demo24.tld/"
    wrapped = b"<?php eval(base64_decode('" + base64.b64encode(inner) + b"'));"
    shallow = set(classify(wrapped, ctx, cust)[0])
    deep = set(classify_deep(wrapped, ctx, cust)[0])
    case("classify() over the wrapper alone", sorted(shallow), ["clean"])
    case("classify_deep() sees through it", "secret" in deep and "identity" in deep, True)
    case("and it says which tags only the layers showed",
         classify_deep(wrapped, ctx, cust)[1]["_read"]["tags_only_in_layers"] != [], True)
    # the control's control: an UNENCODED clean blob must stay clean through the deep form
    case("classify_deep does not manufacture a tag on clean bytes",
         sorted(classify_deep(b"<?php echo 1;", ctx, cust)[0]), ["clean"])

    print("4. every secret shape is classified as gateable or not")
    names = {n for _p, n in SECRET_PATTERNS}
    case("SHAPE_KIND covers SECRET_PATTERNS", sorted(names - set(SHAPE_KIND)), [])
    case("and classifies each as one of two kinds",
         sorted(set(SHAPE_KIND.values())), ["name-only", "value-bearing"])

    print("5. reconcile() returns each cause on an input built to produce it")
    case("no credential anywhere", reconcile(b"<?php echo 1;")["cause"], "agree")
    case("a bare constant name", reconcile(b"define('AUTH_KEY', X);")["cause"], "name-only")
    # Both of these read `gate-cannot-see` until the gate was repaired. They are kept as
    # `agree` rather than deleted: a control that only ever asserted the broken state would
    # have gone green again the day somebody narrowed the gate back.
    case("a complete PEM block, which the gate now has a shape for",
         reconcile(b"-----BEGIN RSA PRIVATE KEY-----\nQUFBQUFBQUFBQUFBQUFB\n"
                   b"-----END RSA PRIVATE KEY-----")["cause"], "agree")
    # And the state the two real rows are actually in: a marker quoted in documentation,
    # with no key body and no closing marker. The TAGGER matches it, the gate correctly does
    # not, and `reconcile` classifies by pattern so it reports the divergence - which is the
    # honest answer, because the pattern is value-bearing and this instance is not.
    case("a PEM header in prose, with no key body",
         reconcile(b"# the headers, e.g. `-----BEGIN RSA PRIVATE KEY-----MIIBOgIBAAJBAK`"
                   )["cause"], "gate-cannot-see")
    case("a password on a name the gate's lookbehind used to block",
         reconcile(b"$user_password = 'hunter2xx';")["cause"], "agree")
    case("`pwd`, which the gate had no keyword for",
         reconcile(b"$pwd = 'hunter2xx';")["cause"], "agree")
    case("a password both sides can see", reconcile(b"$password = 'hunter2xx';")["cause"],
         "agree")

    print("6. this module is outside the gate's tools digest")
    sys.path.insert(0, HERE)
    import gate_provenance
    case("sensitivity.py is not in gate_provenance.TOOLS",
         "sensitivity.py" in gate_provenance.TOOLS, False)
    case("its own digest is 12 hex characters", len(digest()) == 12 and
         all(c in "0123456789abcdef" for c in digest()), True)

    for f in failures:
        print("FAIL:", f)
    print("\n%s" % ("all controls passed" if not failures
                    else "%d control(s) FAILED" % len(failures)))
    return 1 if failures else 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", help="sample files to classify")
    ap.add_argument("--map", default=os.path.join("trail-data", "incoming", "2026-09-03",
                                                  "private", "account-mapping.json"))
    ap.add_argument("--deep", action="store_true",
                    help="classify over decoded layers as well as the raw bytes")
    ap.add_argument("--reconcile", action="store_true",
                    help="report why the tagger and the gate disagree about credentials")
    ap.add_argument("--digest", action="store_true")
    ap.add_argument("--verify-reference", action="store_true")
    ap.add_argument("--assert-digest-unmoved", metavar="DIGEST",
                    help="fail unless gate_provenance.tools_digest() equals DIGEST")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()

    if a.inject:
        return inject()
    if a.digest:
        print("sensitivity rule digest : %s" % digest())
        state, d = reference_digest()
        print("untracked reference     : %s%s" % (state, " (%s)" % d[:12] if d else ""))
        return 0
    if a.assert_digest_unmoved:
        sys.path.insert(0, HERE)
        import gate_provenance
        now = gate_provenance.tools_digest()
        ok = now == a.assert_digest_unmoved
        print("gate_provenance.tools_digest() = %s, expected %s: %s"
              % (now, a.assert_digest_unmoved, "unmoved" if ok else "MOVED"))
        return 0 if ok else 1
    if a.verify_reference:
        state, d = reference_digest()
        print("reference: %s" % REFERENCE)
        print("state    : %s" % state)
        if d:
            print("digest   : %s (recorded %s)" % (d, REFERENCE_DIGEST))
        if state == "absent":
            print("\nThe original is gitignored and out of repo, so this is the normal answer\n"
                  "for anyone but the collector. It is reported rather than passed.")
        return 0 if state in ("ok", "absent") else 1

    if not a.files:
        return ap.error("give some files, or --inject / --digest / --verify-reference")
    m = json.load(open(a.map, encoding="utf-8"))
    ctx = build(m["mapping"], m["domains"])
    cust = set(m["domains"])
    out = {}
    for p in a.files:
        data = open(p, "rb").read()
        layers = vcm().decode_layers(data) if (a.deep or a.reconcile) else []
        rec = {}
        if a.deep:
            tags, ev = classify_deep(data, ctx, cust, layers=layers)
            rec["tags"] = tags
            rec["read"] = ev.get("_read")
        else:
            rec["tags"] = classify(data, ctx, cust)[0]
        if a.reconcile:
            rec["reconcile"] = reconcile(data, layers=layers)
        out[os.path.basename(p)] = rec
    # Categories and counts only. §5.3's seventh failure was a gate result whose contents
    # were the names of the identifiers it had just found.
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
