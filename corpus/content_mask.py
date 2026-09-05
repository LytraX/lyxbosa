#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§5.1 masking of sample BYTES, as opposed to index rows.

`incident_mask.py` rewrites what the index says about a sample. This rewrites what the
sample says about its victim, and the two jobs differ in one property that changes every
decision below: an index row is a record and may be reshaped freely, while a sample is
evidence whose value is that it demonstrates a detection. §5.1: "a substitution that changes
a file's size can change whether it is detected, which would make the fixture test the mask
instead of the malware."

So **every substitution here is length-preserving**, and `mask()` refuses to return a
different length rather than trusting that it did not produce one.

WHAT IS INHERITED, AND WHY THAT IS THE WHOLE POINT
--------------------------------------------------
The hard part of masking is not the replacing, it is deciding WHICH SPANS may be replaced.
§5.3 records twelve failures and the two that keep recurring are both span-selection: a bare
token rule rewrote `wp-content`, `wp-admin` and the string literal `"wp_based"`, and a
segment-prefix rule missed `php56-<acct>.conf.bak` and `_home_<acct>_public_html_`. That
question was answered once, by measurement, in `incident_mask.tiers()`: each identifier gets
the widest rule its own collisions against the stock CMS trees permit, and the answer is
stored in the map because which names collide is a fact about the names.

`ContentMasker` therefore **subclasses** `incident_mask.Masker` and overrides nothing except
the replacement. Span selection - the tiers, the positional rules for names too short to be
anything but positional, the keep-list stash that protects an attacker-created identifier
from being rewritten into uselessness - is the same code, so there is exactly one answer to
which spans are the customer's and it cannot drift between the two maskers.

The sixth recorded failure was a content masker that shipped as a separate implementation
and re-made a collision the index masker had already solved. Inheritance is the structural
fix for that, not a convenience.

WHERE THIS DELIBERATELY DIFFERS FROM THE INDEX MASKER
-----------------------------------------------------
Two places, both because over-matching has a different price here.

  * §5.6 says an identifier regex should err towards over-matching, because "masking a few
    extra characters of an unrelated token costs nothing". In an index row that is true. In
    a sample it is false: an unrelated token rewritten inside working code is a corrupted
    sample, and a corrupted sample that still detects passes every gate. The keep-list
    already carries the tokens where this is known to happen, and `--collisions` is what
    proves the rest.
  * A domain's public suffix is preserved. It identifies nobody, and rewriting `.com` to
    three other letters is a change to a literal a rule may match for no gain in safety.

WHAT IS NOT MASKED, AND WHY EACH REFUSAL IS A DECISION
------------------------------------------------------
  * `c2` - attacker infrastructure is the IOC and is not the customer's (§4.1).
  * Reserved documentation names (RFC 2606 / RFC 6761: `example.*`, `.invalid`, `.test`,
    `.localhost`) and reserved IPv4 addresses. A vendored library's docblock full of
    `user@example.com` is not a leak, and rewriting it is corruption with no benefit.
  * Dotted quads inside comments. `RFC2821 section 4.5.3.2` is four numbers under 256 and
    is not an address; masking it edits a vendored docblock. This is §5.3's ninth failure
    in a new place - a tagger that matched the SHAPE of a personal field rather than a
    value - so the rule states what an address is allowed to look like rather than hunting
    for what it is not, and `--inject` carries controls for both halves.

ENCODED LAYERS
--------------
§5.4 holds that a sample whose encoded layer carries an identifier is not publishable,
because decoding, masking and re-encoding "moves every offset after it". That is true of a
COMPRESSED layer, whose output length is a function of its content, and it is false of a
plain base64 layer: base64 is a fixed 3-to-4 block code, so a length-preserving substitution
in the decoded bytes produces an encoded region of exactly the same length, differing only in
the characters covering the bytes that changed. Nothing after it moves.

`mask_encoded_layers()` therefore repairs the base64 case and only the base64 case, under
five conditions checked per region rather than argued once: the region must decode, it must
re-encode to itself byte for byte (a non-canonical encoding cannot be spliced), the
substitution must preserve length in the decoded domain, the spliced file must have the same
total length, and every byte outside the spliced regions must be unchanged. A region that
fails any of them is left alone and reported, and the encoded-layer gate then fails the
sample, which is the outcome §5.4 wants for the case §5.4 was written about.

The map is out of repo (`incident_mask.MAP_PATH`) and no real name appears in this file,
deliberately - §5.3. Nothing here is executed against a sample; every decode is static.
"""
import hashlib, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import incident_mask                                                    # noqa: E402

LOWER = "abcdefghijklmnopqrstuvwxyz"
ALNUM = LOWER + "0123456789"
HEX = "0123456789abcdef"
B64A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"

# RFC 2606 and RFC 6761 reserved names. A host under one of these belongs to nobody, which
# is exactly what makes it the address a vendored library's documentation uses.
RESERVED_HOSTS = ("example.com", "example.net", "example.org", "example.edu")
RESERVED_TLDS = ("invalid", "test", "localhost", "example", "local")

# Addresses that are not anybody's host. `0.0.0.0` appears in IP-anonymisation helpers as a
# return value; masking it changes what the helper returns.
RESERVED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.2.3.4", "8.8.8.8"}

# Public suffixes of two labels, so the owner's label is the third from the right. Shared
# with the index masker rather than re-listed: one list, one answer.
MULTI_SUFFIX = incident_mask.MULTI_SUFFIX


def _det(seed, alphabet, n):
    """A deterministic string of length `n` over `alphabet`, keyed on `seed`.

    Deterministic because §5.1 requires the same identifier to map to the same replacement
    in every file: a page cache that references a domain must still match the config, or the
    corpus stops being coherent. Keyed on the identifier itself rather than on a counter, so
    the answer does not depend on the order files were processed in.
    """
    out, h, i = [], hashlib.sha256(seed).digest(), 0
    while len(out) < n:
        if i >= len(h):
            h = hashlib.sha256(h).digest()
            i = 0
        out.append(alphabet[h[i] % len(alphabet)])
        i += 1
    return "".join(out)


# The marker every synthetic value carries when its length allows one.  Deliberately NOT
# `acct`, `site`, `srv` or `demo`: those are the map's own pseudonym namespaces and a
# length-preserving synthetic cannot use them without aliasing a real mapped account - an
# 8-character name would become `acct1234` and a 6-character one `acct47`, which is a
# pseudonym the map has already given to somebody else.  Conflating two customers is worse
# than splitting one, which the legacy map's own note already says.
MARKER = "mask"


def _synthetic(original, alphabet=ALNUM, seed_prefix=b"acct"):
    """A same-length replacement that says it is one.

    §7.2's map-free invariants work by asserting the FORM of what is allowed rather than
    hunting for what is not - `shard-gate.py` requires every `/home*/<x>/` in a published row
    to be `acctNN`, "and it does not need to know which names are real: anything that is not a
    pseudonym is wrong."  That discipline is only available over shipped BYTES if the bytes
    carry a recognisable form too, and a replacement of random lowercase forecloses it: a
    reader of a published sample, and any future gate over one, cannot tell a synthetic
    account from a real one.

    So the marker goes in wherever the length allows, and a name too short to hold it plus
    enough entropy falls back to opaque letters.  Length is never traded for legibility -
    §5.1 comes first - and legibility is never traded for injectivity: the marker costs four
    of the available characters, and at three remaining it is already a 46,656-value space
    that `collisions_between_replacements()` measured at zero clashes over this map and would
    refuse if that ever stopped being true.  At two remaining it clashed on the first run,
    which is why the floor is where it is rather than where it looked reasonable.
    """
    room = len(original) - len(MARKER)
    if room >= 3:
        return MARKER + _det(seed_prefix + original.lower().encode(), alphabet, room)
    return _det(seed_prefix + original.lower().encode(), LOWER, len(original))


def _like(original, replacement):
    """`replacement` recased to follow `original`, so a titlecased occurrence stays one.

    Cosmetic in a path and not cosmetic in code: a substitution that turns `Backup` into
    `qxtmzp` inside an identifier that the sample also declares elsewhere reads as a
    different symbol to anyone auditing the shipped bytes.
    """
    out = []
    for c, r in zip(original, replacement):
        out.append(r.upper() if c.isupper() else r)
    return "".join(out)


def _public_suffix_len(labels):
    """How many trailing labels of a hostname are the public suffix, as a count of labels."""
    if len(labels) >= 3 and ".".join(labels[-2:]).lower() in MULTI_SUFFIX:
        return 2
    return 1 if len(labels) >= 2 else 0


def mask_hostname(host, seed_prefix=b"dom"):
    """Every label except the public suffix, length-preserved.

    The suffix stays because it identifies nobody and because it is a literal a rule may
    match: §5.1's warning about masking changing detection cuts both ways, and the cheapest
    way not to change a detection is not to change bytes that carry no identity.
    """
    labels = host.split(".")
    keep = _public_suffix_len(labels)
    n = len(labels) - keep
    if n <= 0:
        return host
    out = [_like(l, _synthetic(l, seed_prefix=seed_prefix)) for l in labels[:n]]
    return ".".join(out + labels[n:])


def is_reserved_host(host):
    h = host.lower().rstrip(".")
    return h in RESERVED_HOSTS or h.rsplit(".", 1)[-1] in RESERVED_TLDS


class ContentMasker(incident_mask.Masker):
    """Span selection from `incident_mask.Masker`; replacement length-preserving.

    `incident_mask.Masker.mask()` cannot be reused as-is for two reasons that are both about
    it being a row masker: it short-circuits on a 64-hex string (a sha256 field, meaningless
    in a sample), and it substitutes pseudonyms, which change length. Everything that decides
    WHICH bytes may change - `rx_domain`, `rx_a/b/c`, `positional`, `keep_rx` - is inherited
    untouched.
    """

    def __init__(self, m, vocabulary=None):
        incident_mask.Masker.__init__(self, m)
        self.changes = []
        self.demoted = []
        if vocabulary is not None:
            self._demote_stock_words(vocabulary)

    def _demote_stock_words(self, vocab):
        """An identifier that IS a stock-CMS token is masked positionally and nowhere else.

        `incident_mask.tiers()` gets this right now and the map does not: tiers are computed
        once and stored, so a name tiered before the fix keeps its stored tier. Over an index
        row a wrong tier over-masks a path segment, which is untidy. Over sample bytes it
        rewrites a working identifier inside code, and §5.3's sixth failure is precisely that
        - a content masker rewriting a string literal because a bare-token rule matched a
        CMS-shaped name. So the byte masker re-derives the tier from the vocabulary it is
        given rather than trusting the stored one, and says how many it moved.
        """
        bare = [k for k in self.pairs if not ("." in k and not k.startswith("."))]
        eff = {}
        for b in bare:
            stored = self.tier.get(b, "C" if len(b) >= 3 else "D")
            if b in vocab and stored != "D":
                eff[b] = "D"
                self.demoted.append({"identifier_len": len(b), "from": stored, "to": "D"})
            else:
                eff[b] = stored

        def of(t):
            return [b for b in bare if eff[b] == t]
        self.rx_a = self._rx(of("A"), "", "")
        self.rx_b = self._rx(of("B"), r"(?<![A-Za-z0-9])", "")
        self.rx_c = self._rx(of("C"), r"(?<![A-Za-z0-9])", r"(?![A-Za-z])")
        self.positional = []
        for d in of("D"):
            e = re.escape(d)
            self.positional += [
                (re.compile(r"(?<=/home/)" + e + r"(?=[/\"'\\\s]|$)", re.I), d),
                (re.compile(r"(?<![A-Za-z0-9])(?<=_home_)" + e + r"(?=_)", re.I), d),
                (re.compile(r"(?<=/home\d/)" + e + r"(?=[/\"'\\\s]|$)", re.I), d),
                (re.compile(r"(?<![A-Za-z0-9])" + e + r"(?=_public_html)", re.I), d),
                (re.compile(r"(?<=php\d\d-)" + e + r"(?=\.conf)", re.I), d),
            ]

    # -- replacement ------------------------------------------------------------------
    def _log(self, kind, before, after):
        if len(before) != len(after):
            raise AssertionError("content masking must preserve length: %s %d -> %d"
                                 % (kind, len(before), len(after)))
        self.changes.append({"kind": kind, "len": len(before)})

    def _replace_identifier(self, text):
        """One matched identifier -> a same-length synthetic. Never the map's pseudonym:
        `acctNN` is six characters and an account name is not."""
        if "." in text and not text.startswith("."):
            rep = mask_hostname(text)
            kind = "domain"
        else:
            rep = _like(text, _synthetic(text))
            kind = "account"
        self._log(kind, text, rep)
        return rep

    def _sub(self, mo):                                   # overrides the row masker's
        return self._replace_identifier(mo.group(1))

    def mask_identifiers(self, text):
        """Mapped identifiers only. Same spans as the index masker, different bytes."""
        holes, out = [], text
        if self.keep_rx:                                  # protect kept spans first (§4.1)
            def stash(mo):
                holes.append(mo.group(0))
                return "\x00%d\x00" % (len(holes) - 1)
            out = self.keep_rx.sub(stash, out)
        for rx in (self.rx_domain, self.rx_a, self.rx_b, self.rx_c):
            if rx:
                out = rx.sub(self._sub, out)
        for rx, name in self.positional:
            out = rx.sub(lambda mo: self._replace_identifier(mo.group(0)), out)
        for i, original in enumerate(holes):
            out = out.replace("\x00%d\x00" % i, original)
        if len(out) != len(text):
            raise AssertionError("identifier masking changed length %d -> %d"
                                 % (len(text), len(out)))
        return out


# ---------------------------------------------------------------------------------------
# Classes of identifier that no map can name, because they are not this incident's
# customers: a third party's account and site written into the sample by the attacker.
# These are masked POSITIONALLY - the slot says what the value is - which is the same rule
# §5.3 gives for a colliding name, applied to a value nothing can look up.
#
# `shard-gate.py` already asserts the mirror of this over index rows: every `/home*/<x>/`
# must have <x> in `acctNN` form, "and it does not need to know which names are real:
# anything that is not a pseudonym is wrong". A positive form rule is the only kind that
# can cover a name that is in no map.
# ---------------------------------------------------------------------------------------
# The trailing guard is a NEGATIVE lookahead - "not a character that could continue this
# value" - rather than a positive list of the delimiters that were expected to follow.
#
# It was a positive list, and it cost two occurrences immediately: an example path written
# into a page as `/home/<acct>/<domain><br>` ends at `<`, which was not on the list, so the
# account was masked and the site name beside it was not.  §5.6 records exactly this twice
# already - "a customer domain surviving because the regex lookbehind blocked a match after
# `.`, and another surviving because a lookahead blocked a match before a digit" - and gives
# the rule: lookarounds in an identifier regex should err towards over-matching, because
# masking a few extra characters costs nothing and leaving a customer domain costs
# everything.  A positive list of delimiters is a promise to have thought of all of them.
HOME_SLOT = re.compile(r"(?<=/home)(\d*)(/)([A-Za-z0-9._-]{2,32})(?![A-Za-z0-9._-])")
HOME_ENC_SLOT = re.compile(r"(?<=_home)(\d*)(_)([A-Za-z0-9.-]{2,32})(?=_)")
DOCROOT_SLOT = re.compile(r"(?<=/home)(\d*)(/)([A-Za-z0-9._-]{2,32})(/)"
                          r"([A-Za-z0-9-]{2,63}(?:\.[A-Za-z0-9-]{2,63})+)(?![A-Za-z0-9-])")
PSEUDONYM = re.compile(r"^(acct\d+|site\d+|srv\d+|demo\d+)$", re.I)


class SlotMasker(object):
    """Account- and docroot-shaped values in a slot where only an account can sit.

    Deliberately not map-driven. The sample this exists for is a deployment tool whose UI
    carries an example path naming a third party's account and site; neither is in either
    map, so a map-driven masker cannot see them and a substring sweep cannot tell them from
    the two placeholder names beside them. The slot can.
    """

    def __init__(self, keep=()):
        self.keep = {k.lower() for k in keep}
        self.changes = []

    def _log(self, kind, before, after):
        if len(before) != len(after):
            raise AssertionError("slot masking must preserve length")
        self.changes.append({"kind": kind, "len": len(before)})

    def _acct(self, value):
        if PSEUDONYM.match(value) or value.lower() in self.keep:
            return value
        rep = _like(value, _synthetic(value, seed_prefix=b"slot"))
        self._log("account-slot", value, rep)
        return rep

    def _docroot(self, value):
        if is_reserved_host(value) or value.lower() in self.keep:
            return value
        rep = mask_hostname(value, b"slotdom")
        if rep != value:
            self._log("docroot-slot", value, rep)
        return rep

    def mask(self, text):
        def _dr(mo):
            return ("%s%s%s%s%s" % (mo.group(1), mo.group(2), self._acct(mo.group(3)),
                                    mo.group(4), self._docroot(mo.group(5))))
        out = DOCROOT_SLOT.sub(_dr, text)
        out = HOME_SLOT.sub(lambda mo: "%s%s%s" % (mo.group(1), mo.group(2),
                                                   self._acct(mo.group(3))), out)
        out = HOME_ENC_SLOT.sub(lambda mo: "%s%s%s" % (mo.group(1), mo.group(2),
                                                       self._acct(mo.group(3))), out)
        if len(out) != len(text):
            raise AssertionError("slot masking changed length")
        return out


# ---------------------------------------------------------------------------------------
# Secrets. §5.1: "replace with a synthetic value of the same shape and length - a 64-hex
# salt stays 64 hex, a bcrypt hash stays a valid-looking bcrypt hash". Shape matters because
# a rule may match the shape; the value must not survive because §7.2's secret scan has to
# return zero hits over a public shard, and that scan cannot tell whose secret it is.
# ---------------------------------------------------------------------------------------
WP_CONST = re.compile(r"((?:DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|"
                      r"LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|"
                      r"LOGGED_IN_SALT|NONCE_SALT)\W{1,12})(['\"])([^'\"]{2,})\2")
QUOTED_SECRET = re.compile(r"((?<![A-Za-z0-9_])(?:password|passwd|pass|api_key|apikey|secret)"
                           r"(?![A-Za-z0-9_])\s*[=:]>?\s*)"
                           r"(['\"])([^'\"]{4,})\2", re.I)
BCRYPT = re.compile(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}")
PHPASS = re.compile(r"\$P\$[./A-Za-z0-9]{31}")
HEX_DIGEST = re.compile(r"(?<![0-9A-Za-z])([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})"
                        r"(?![0-9A-Za-z])")
EMAIL = re.compile(r"([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24})")
IPV4 = re.compile(r"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![0-9.])")

# A dotted quad inside a comment is a section number often enough that masking one is a
# routine way to corrupt a vendored docblock. Comments are found rather than parsed: the
# spans below are conservative and a miss costs an unmasked comment, not an unmasked address.
COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*|^[ \t]*#[^\n]*|<!--.*?-->", re.S | re.M)


class SecretMasker(object):
    """Credential-shaped literals, each replaced by a synthetic of the same shape and length.

    `mask_hex_digests` is off by default and that is a measured decision rather than caution.
    A bare hex digest is a digest of SOMETHING, and in this collection every one adjudicated
    in context was something that must not be rewritten: two attacker file markers in
    comments, an example value in a panel's own help text, and a host-binding hash the
    payload compares against the victim file's contents at run time. None is a stored
    credential, no row's `secret` evidence names one - the evidence names bcrypt hashes,
    literal passwords, wp-config credentials and salts - and masking one destroys an IOC or a
    literal the sample's own logic depends on. Turn it on for a round that has real ones.
    """

    def __init__(self, keep_hosts=(), mask_ipv4=False, mask_hex_digests=False):
        self.keep = {h.lower() for h in keep_hosts}
        self.mask_ipv4 = mask_ipv4
        self.mask_hex_digests = mask_hex_digests
        self.changes = []
        self.skipped = []

    def _log(self, kind, before, after):
        if len(before) != len(after):
            raise AssertionError("secret masking must preserve length: %s" % kind)
        self.changes.append({"kind": kind, "len": len(before)})

    def _value(self, v, kind):
        rep = _det(b"sec" + v.encode("latin-1"), ALNUM, len(v))
        self._log(kind, v, rep)
        return rep

    def _wp_const(self, mo):
        return mo.group(1) + mo.group(2) + self._value(mo.group(3), "wp-config-constant") \
            + mo.group(2)

    def _quoted(self, mo):
        return mo.group(1) + mo.group(2) + self._value(mo.group(3), "quoted-secret") \
            + mo.group(2)

    def _bcrypt(self, mo):
        v = mo.group(0)
        rep = v[:7] + _det(b"bc" + v.encode("latin-1"), B64A, len(v) - 7)
        self._log("bcrypt", v, rep)
        return rep

    def _phpass(self, mo):
        v = mo.group(0)
        rep = v[:4] + _det(b"pp" + v.encode("latin-1"), B64A, len(v) - 4)
        self._log("phpass", v, rep)
        return rep

    def _hex(self, mo):
        v = mo.group(1)
        rep = _det(b"hex" + v.encode("latin-1"), HEX, len(v))
        self._log("hex-digest", v, rep)
        return rep

    def _email(self, mo):
        loc, host = mo.group(1), mo.group(2)
        if is_reserved_host(host) or host.lower() in self.keep:
            self.skipped.append({"kind": "email", "reason": "reserved-or-kept-host"})
            return mo.group(0)
        rep = _synthetic(loc, seed_prefix=b"loc") + "@" + mask_hostname(host)
        self._log("email", mo.group(0), rep)
        return rep

    def _ip(self, mo):
        v = mo.group(1)
        if v in RESERVED_IPS or any(int(x) > 255 for x in v.split(".")):
            self.skipped.append({"kind": "ipv4", "reason": "reserved-or-not-an-address"})
            return v
        h = hashlib.sha256(b"ip" + v.encode()).digest()
        cand = "10.%d.%d.%d" % (h[0], h[1], h[2] or 1)
        cand = (cand[:len(v)] if len(cand) > len(v)
                else cand + _det(b"ipad" + v.encode(), "0123456789", len(v) - len(cand)))
        self._log("ipv4", v, cand)
        return cand

    def mask(self, text):
        out = WP_CONST.sub(self._wp_const, text)
        out = QUOTED_SECRET.sub(self._quoted, out)
        out = BCRYPT.sub(self._bcrypt, out)
        out = PHPASS.sub(self._phpass, out)
        if self.mask_hex_digests:
            out = HEX_DIGEST.sub(self._hex, out)
        else:
            n = len(HEX_DIGEST.findall(out))
            if n:
                self.skipped += [{"kind": "hex-digest", "reason": "not-a-tagged-secret"}] * n
        out = EMAIL.sub(self._email, out)
        if self.mask_ipv4:
            spans = [(m.start(), m.end()) for m in COMMENTS.finditer(out)]

            def in_comment(i):
                return any(a <= i < b for a, b in spans)
            pieces, last = [], 0
            for m in IPV4.finditer(out):
                if in_comment(m.start()):
                    self.skipped.append({"kind": "ipv4", "reason": "inside-a-comment"})
                    continue
                pieces.append(out[last:m.start()])
                pieces.append(self._ip(m))
                last = m.end()
            pieces.append(out[last:])
            out = "".join(pieces)
        if len(out) != len(text):
            raise AssertionError("secret masking changed length %d -> %d"
                                 % (len(text), len(out)))
        return out


# ---------------------------------------------------------------------------------------
# The whole pass over one sample.
# ---------------------------------------------------------------------------------------
B64_RUN = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")


def mask_plaintext(text, masker, slots, secrets):
    """Order: secrets, then mapped identifiers, then slots.

    Secrets first because a secret's VALUE can contain domain-looking text, and a domain
    rule that fires inside a password rewrites part of a literal it does not understand.
    Slots last because a slot's value may already have been masked as a mapped identifier,
    and a slot masker that then re-masks a pseudonym would undo the map's determinism.
    """
    out = secrets.mask(text)
    out = masker.mask_identifiers(out)
    out = slots.mask(out)
    return out


def mask_encoded_layers(data, mask_text, depth=0, max_depth=4, report=None):
    """Repair identifiers inside plain base64 layers, or refuse and say so.

    Five conditions per region, all checked rather than argued - see the module docstring.
    Returns the possibly-rewritten bytes; `report` collects one entry per region acted on or
    refused, by CATEGORY only. §5.3's seventh failure was a gate that stored the identifiers
    it found, so nothing here records a value.
    """
    import base64
    if report is None:
        report = []
    if depth >= max_depth:
        return data
    out = bytearray(data)
    for m in reversed(list(B64_RUN.finditer(data))):
        region = m.group(0)
        try:
            decoded = base64.b64decode(region + b"=" * (-len(region) % 4), validate=True)
        except Exception:
            continue                       # not base64 at all; an ordinary alphanumeric run
        if not decoded:
            continue
        canonical = base64.b64encode(decoded)
        if canonical == region:
            strip = False                  # padded, exactly as this encoder would write it
        elif canonical.rstrip(b"=") == region:
            strip = True                   # unpadded, which splices just as exactly
        else:
            # Decodes, but this encoder does not reproduce it byte for byte: wrapped lines,
            # a custom alphabet, or non-zero bits in the final padding group. Splicing would
            # rewrite bytes that are not the identifier and could move what follows. Left
            # alone on purpose; if the region carried an identifier the encoded-layer gate
            # fails the sample, which is the right outcome rather than a silent partial mask.
            #
            # Most of these are not encoded layers at all - an alphanumeric run in a URL, a
            # character-set literal, a long PHP identifier - and calling them all "an encoded
            # layer left unmasked" makes the record say something alarming and false. The two
            # are separated by whether the decode is text, which is the same distinction
            # §5.3's eighth failure is about: "there is a layer I could not open" and "there
            # is no layer" are different facts and only one of them is a reason to hold.
            printable = sum(1 for c in decoded if 32 <= c < 127 or c in (9, 10, 13))
            looks_like_a_layer = printable / float(len(decoded)) > 0.80
            report.append({"region": ("non-canonical-base64" if looks_like_a_layer
                                      else "alphanumeric-run-not-a-layer"),
                           "action": "left-unmasked", "depth": depth})
            continue
        try:
            inner_text = decoded.decode("latin-1")
            masked = mask_text(inner_text).encode("latin-1")
        except AssertionError:
            report.append({"region": "base64", "action": "refused-length-change",
                           "depth": depth})
            continue
        masked = mask_encoded_layers(masked, mask_text, depth + 1, max_depth, report)
        if masked == decoded:
            continue
        if len(masked) != len(decoded):
            report.append({"region": "base64", "action": "refused-length-change",
                           "depth": depth})
            continue
        new_region = base64.b64encode(masked)
        if strip:
            new_region = new_region.rstrip(b"=")
        if len(new_region) != len(region):
            report.append({"region": "base64", "action": "refused-reencode-length",
                           "depth": depth})
            continue
        out[m.start():m.end()] = new_region
        report.append({"region": "base64", "action": "masked", "depth": depth,
                       "decoded_bytes": len(decoded)})
    return bytes(out)


def mask_sample(data, m, mask_ipv4=False, vocabulary=None, mask_hex_digests=False):
    """Mask one sample's bytes. Returns (masked_bytes, detail).

    `detail` carries kinds and counts and never a value - the seventh recorded failure was a
    gate result that stored the names of the identifiers it had just found.
    """
    clashes = collisions_between_replacements(m)
    if clashes:
        raise AssertionError("two identifiers mask to the same value (%d clash(es), shapes "
                             "%r); refusing to conflate two customers behind one pseudonym"
                             % (len(clashes), clashes))
    masker = ContentMasker(m, vocabulary=vocabulary)
    slots = SlotMasker(keep=m.get("keep") or ())
    secrets = SecretMasker(keep_hosts=m.get("keep") or (), mask_ipv4=mask_ipv4,
                           mask_hex_digests=mask_hex_digests)
    text = data.decode("latin-1")

    def _text(t):
        return mask_plaintext(t, masker, slots, secrets)

    plain = _text(text).encode("latin-1")
    layers = []
    out = mask_encoded_layers(plain, _text, report=layers)

    if len(out) != len(data):
        raise AssertionError("masking changed the sample's length %d -> %d"
                             % (len(data), len(out)))
    changes = masker.changes + slots.changes + secrets.changes
    kinds = sorted({c["kind"] for c in changes})
    return out, {
        "changes": len(changes),
        "change_kinds": kinds,
        "length_preserved": True,
        "encoded_regions": layers,
        "skipped": _tally(secrets.skipped),
        "tiers_demoted_against_vocabulary": len(masker.demoted),
    }


def collisions_between_replacements(m, extra=()):
    """Two distinct identifiers that would mask to the same value.  Measured, not assumed.

    A synthetic is `mask` plus a few characters derived from a hash, so the space it draws
    from is small for a short name: an eight-character account has four characters of
    entropy.  Conflating two customers behind one pseudonym is a worse error than splitting
    one across two - the legacy map's own note says so - and it is invisible afterwards,
    because the output looks exactly like a correct mask.  So it is checked rather than
    argued, over every identifier the map holds plus anything the caller has seen in a slot.
    """
    seen, clashes = {}, []
    names = [k for k in incident_mask.pairs(m)] + list(extra)
    for n in names:
        rep = mask_hostname(n) if ("." in n and not n.startswith(".")) else _synthetic(n)
        if rep in seen and seen[rep] != n:
            clashes.append({"length": len(n), "kind": "domain" if "." in n else "account"})
        seen[rep] = n
    return clashes


def _tally(items):
    out = {}
    for it in items:
        k = "%s:%s" % (it["kind"], it["reason"])
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------------------
# Controls. AGENTS.md: a check that has never been observed to fail is not yet a check, and
# every checker in corpus/ carries the control that shows it can say the other thing.
#
# For a MASKER the controls that matter are the two ways it can be wrong: it can fail to
# rewrite an identifier, and it can rewrite something that is not one. Both halves are here,
# and the second is the one this component has already got wrong once in production.
# ---------------------------------------------------------------------------------------
POSITIVE = [
    ("account in a path constant",       "$p = '/home/%(long)s/public_html/index.php';"),
    ("account under /home2",             "$p = '/home2/%(long)s/public_html/x.php';"),
    ("underscore-encoded quarantine",    "_home_%(long)s_public_html_wp-admin.php"),
    ("account glued to a token",         "$f = 'Backup%(long)s0304.zip';"),
    ("account as a DB name prefix",      "define('DB_NAME', '%(long)s_db');"),
    ("account inside a URL path",        "$u = 'https://cdn.example.net/c/%(long)s-jb.html';"),
    ("account in a php-fpm conf name",   "$c = 'php56-%(long)s.conf.bak';"),
    ("account followed by markup",        "Example: /home/%(long)s/site.example<br>"),
]

# Values in an account or docroot slot that no map can name.  A map-driven masker cannot see
# these at all, so the slot rules are what cover them and these are their controls.
SLOT_POSITIVE = [
    ("a third party's account in a slot",   "Example format: /home/cepinxxl/index.php"),
    ("an account and site before markup",   "/home/cepinxxl/somewhere-else.tld<br>"),
    ("an underscore-encoded slot",          "$f = '_home_cepinxxl_public_html_x.php';"),
]
SLOT_NEGATIVE = [
    ("a pseudonym in the slot",             "/home/acct01/public_html/index.php"),
    ("a reserved documentation host",       "/home/someuser/example.com<br>"),
]

SECRET_POSITIVE = [
    ("a quoted password literal",        "$password = \"vdapjkvtfq\"; session_start();"),
    ("a shorter password variable",      "$pass = '713@.Ze,/#*Be&^13%37?dX!';"),
    ("a wp-config credential",           "define('DB_PASSWORD', 'LnDZYpxBj5I2');"),
    ("a bcrypt gate hash",
     "$h = '$2y$10$" + "a" * 53 + "';"),
]

# The half that is load-bearing. Every one of these is a real form from this corpus or from
# the stock CMS trees, and a masker that rewrites any of them has corrupted a sample while
# still passing an identifier gate, which is the failure mode with no external symptom.
NEGATIVE = [
    ("CMS token starting with a short name", "require ABSPATH . 'wp-content/plugins/x.php';"),
    ("a string literal with that prefix",    "$mode = 'wp_based';"),
    ("an ordinary word starting a name",     "// The path to the sendmail program."),
    ("a doc URL containing a short name",    "// @link http://php.net/manual/en/mail.php"),
    ("a documentation address",              "// e.g. user@example.com and joe@example.net"),
    ("an RFC section number in a comment",   "/* from RFC2821 section 4.5.3.2 */"),
    ("the unspecified address",              "if (empty($ip)) { return '0.0.0.0'; }"),
    ("a pseudonym, already masked",          "$p = '/home/acct01/public_html/index.php';"),
    ("an attacker marker in a comment",       "/* d41d8cd98f00b204e9800998ecf8427e */"),
    ("a host-binding digest literal",         "$P = '5d41402abc4b2a76b9719d911017c592';"),
    ("a variable that merely starts 'pass'",  "$passed = 'yes'; $passthru = 'no';"),
]


def _inject(m, vocab_root=None):
    """Feed each form through the masker on its own and assert the verdict both ways."""
    vset = incident_mask.vocabulary(vocab_root) if vocab_root else None

    def mask_sample(data, mm, mask_ipv4=False):        # noqa: F811 - shadows on purpose
        return globals()["mask_sample"](data, mm, mask_ipv4=mask_ipv4, vocabulary=vset)
    accounts = [a for a in m["mapping"] if len(a) >= 6]
    short = [a for a in m["mapping"] if len(a) < 6]
    if not accounts:
        print("no identifier long enough to inject with")
        return 1
    long_name = max(accounts, key=len)
    failures = []

    print("positive controls - the masker must rewrite these")
    for name, form in POSITIVE:
        src = form % {"long": long_name}
        out, detail = mask_sample(src.encode("latin-1"), m)
        moved = out != src.encode("latin-1")
        same_len = len(out) == len(src)
        gone = long_name.lower() not in out.decode("latin-1").lower()
        ok = moved and same_len and gone
        print("   +  %-40s %s" % (name, "masked" if ok else "MISSED"))
        if not ok:
            failures.append(name)

    print()
    print("slot controls - a value no map can name, masked because the slot says what it is")
    for name, form in SLOT_POSITIVE:
        out, _ = mask_sample(form.encode("latin-1"), m)
        ok = out != form.encode("latin-1") and len(out) == len(form) \
            and b"cepinxxl" not in out
        print("   +  %-40s %s" % (name, "masked" if ok else "MISSED"))
        if not ok:
            failures.append(name)
    for name, form in SLOT_NEGATIVE:
        out, _ = mask_sample(form.encode("latin-1"), m)
        # the account half of the reserved-host control may be masked; the HOST must not be
        ok = b"example.com" in out if "example.com" in form else out == form.encode("latin-1")
        print("   -  %-40s %s" % (name, "left alone" if ok else "REWRITTEN"))
        if not ok:
            failures.append(name + " (should not have changed)")

    print()
    print("secret controls - a credential-shaped literal must not survive its own masking")
    for name, form in SECRET_POSITIVE:
        out, _ = mask_sample(form.encode("latin-1"), m)
        ok = out != form.encode("latin-1") and len(out) == len(form)
        print("   +  %-40s %s" % (name, "masked" if ok else "MISSED"))
        if not ok:
            failures.append(name)

    print()
    print("negative controls - the masker must leave these exactly alone")
    for name, form in NEGATIVE:
        out, _ = mask_sample(form.encode("latin-1"), m)
        ok = out == form.encode("latin-1")
        print("   -  %-40s %s" % (name, "unchanged" if ok else "REWRITTEN"))
        if not ok:
            failures.append(name + " (should not have changed)")

    print()
    print("length preservation over every control")
    for _, form in POSITIVE + NEGATIVE:
        src = (form % {"long": long_name}) if "%(long)s" in form else form
        out, _ = mask_sample(src.encode("latin-1"), m)
        if len(out) != len(src):
            failures.append("length changed on a control")
    print("   =  every control returned the same number of bytes: %s"
          % ("no" if any("length" in f for f in failures) else "yes"))

    print()
    print("encoded-layer repair - a base64 layer carrying an identifier")
    import base64
    inner = ("/home/%s/public_html//index.php" % long_name).encode("latin-1")
    blob = base64.b64encode(inner)
    src = b"$x = '" + blob + b"'; eval(base64_decode($x));"
    out, detail = mask_sample(src, m)
    spliced = out != src and len(out) == len(src)
    try:
        back = base64.b64decode(B64_RUN.search(out).group(0), validate=True)
        cleaned = long_name.lower().encode() not in back.lower()
        same_inner_len = len(back) == len(inner)
    except Exception:
        cleaned = same_inner_len = False
    ok = spliced and cleaned and same_inner_len
    print("   +  %-40s %s" % ("identifier inside plain base64",
                              "masked in place" if ok else "MISSED"))
    if not ok:
        failures.append("encoded-layer repair")

    # Unpadded base64 is the common real form and splices just as exactly.
    src1b = b"$x = '" + blob.rstrip(b"=") + b"';"
    out1b, _ = mask_sample(src1b, m)
    try:
        r = B64_RUN.search(out1b).group(0)
        back1b = base64.b64decode(r + b"=" * (-len(r) % 4), validate=True)
        okb = (len(out1b) == len(src1b) and out1b != src1b
               and long_name.lower().encode() not in back1b.lower())
    except Exception:
        okb = False
    print("   +  %-40s %s" % ("identifier inside unpadded base64",
                              "masked in place" if okb else "MISSED"))
    if not okb:
        failures.append("unpadded base64 repair")

    # And the refusal half: a region this encoder cannot reproduce byte for byte must be
    # left alone rather than half-masked, because splicing it rewrites bytes that are not
    # the identifier. Non-zero bits in the final padding group are the real form of this.
    # One byte in the final group leaves four spare bits in the last character, so flipping
    # its low bit yields a region that still decodes to the same bytes and that b64encode
    # will not reproduce.
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    padded = inner + b" " * ((1 - len(inner)) % 3)
    nc = bytearray(base64.b64encode(padded))
    last = len(nc.rstrip(b"=")) - 1
    nc[last] = ord(std[std.index(chr(nc[last])) ^ 1])
    noncanon = bytes(nc)
    src2 = b"$x = '" + noncanon + b"';"
    out2, detail2 = mask_sample(src2, m)
    refused = (out2 == src2 and
               any(r["action"] == "left-unmasked" for r in detail2["encoded_regions"]))
    print("   -  %-40s %s" % ("a region this encoder cannot reproduce",
                              "left alone and reported" if refused else "TOUCHED"))
    if not refused:
        failures.append("a non-reproducible base64 region was modified")

    if vocab_root:
        print()
        mk = ContentMasker(m, vocabulary=vset)
        hits = [t for t in vset if mk.mask_identifiers(t) != t]
        print("   -  %-40s %d token(s) rewritten (%d identifier(s) demoted)"
              % ("stock CMS vocabulary", len(hits), len(mk.demoted)))
        if hits:
            failures.append("rewrites %d stock CMS token(s)" % len(hits))

    print()
    if failures:
        print("FAIL: the masker got %d of its own controls wrong: %s"
              % (len(failures), ", ".join(failures)))
        return 1
    print("every identifier form is masked, every collision form is untouched, and every "
          "control kept its length; the masker can fail, and does not fire on stock code")
    return 0


USAGE = ("usage: content_mask.py --mask <file> [--out <file>] [--map <path>] [--mask-ipv4]\n"
         "       content_mask.py --inject [--vocabulary <stock-cms-root>] [--map <path>]\n"
         "       content_mask.py --collisions <stock-cms-root> [--map <path>]\n"
         "  (this is also a library; see the docstring)")

if __name__ == "__main__":
    import json
    argv = sys.argv[1:]
    mp = incident_mask.MAP_PATH
    if "--map" in argv:
        i = argv.index("--map")
        mp = argv[i + 1]
        del argv[i:i + 2]
    ipv4 = "--mask-ipv4" in argv
    if ipv4:
        argv.remove("--mask-ipv4")
    outp = None
    if "--out" in argv:
        i = argv.index("--out")
        outp = argv[i + 1]
        del argv[i:i + 2]
    vocab = None
    if "--vocabulary" in argv:
        i = argv.index("--vocabulary")
        vocab = argv[i + 1]
        del argv[i:i + 2]

    if argv and argv[0] == "--inject":
        sys.exit(_inject(incident_mask.load_map(mp), vocab))
    if len(argv) == 2 and argv[0] == "--mask":
        m = incident_mask.load_map(mp)
        raw = open(argv[1], "rb").read()
        vset = incident_mask.vocabulary(vocab) if vocab else None
        masked, detail = mask_sample(raw, m, mask_ipv4=ipv4, vocabulary=vset)
        if outp:
            with open(outp, "wb") as fh:
                fh.write(masked)
        print(json.dumps(detail, indent=1, sort_keys=True))
        sys.exit(0)
    if len(argv) == 2 and argv[0] == "--collisions":
        m = incident_mask.load_map(mp)
        v = incident_mask.vocabulary(argv[1])
        mk = ContentMasker(m, vocabulary=v)
        print("identifiers demoted to positional against this vocabulary: %d"
              % len(mk.demoted))
        hits = [t for t in v if mk.mask_identifiers(t) != t]
        for t in sorted(hits):
            print("  %s" % t[:70])
        print("%d token(s) in %s would be rewritten" % (len(hits), argv[1]))
        sys.exit(1 if hits else 0)
    sys.exit(USAGE)
