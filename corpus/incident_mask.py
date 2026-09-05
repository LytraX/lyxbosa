#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Path and prose masking for the CURRENT-incident half of the index.

Sibling of `infected_mask.py`, which does the same job for the legacy `trail-data/Infected`
tree. Two maskers rather than one because the identifiers and the maps are different; one
GATE (`shard-gate.py`) and one CHECK (`verify-infected-mask.py`) cover both, which is the
split that matters - the map is out of repo, so anything a stranger must be able to run
cannot depend on it.

Map: `trail-data/incoming/2026-09-03/private/account-mapping.json`. This module is useless
without it, deliberately (CORPUS_PLAN 5.3): no real name appears in this file, only roles.

WHY THIS EXISTS WHEN A MASKER ALREADY RAN
-----------------------------------------
The masker that first wrote these rows keyed on full account names and tested one direction
only: it asked whether a path segment *starts with* a known account name plus a separator.
Incident-response directories use variants in BOTH directions, and only one was ever
covered:

  * shorter than the recorded name - an account recorded as <a> appearing as `<a'>-safe-
    repair-...` where <a'> is a truncation. Found and fixed at the time.
  * longer than the recorded name - an account recorded as <a> appearing as
    `<a>x-backup-component-validation-<8 digits>-<6 digits>`. NOT found, because
    `segment.startswith(name + "-")` is false when the segment continues with a letter, and
    the gate's `(?<![A-Za-z0-9])<name>(?![A-Za-z0-9])` fails on the same trailing letter.
    2,402 occurrences of one name survived a year of collection that way.

So the rule here is stated as a relation between a token and an identifier that holds in
both directions, and `tiers()` decides HOW WIDE each identifier may match by measuring it
against a vocabulary that contains no customer of ours.

THE FOUR TIERS, AND WHY THE WIDTH IS MEASURED RATHER THAN CHOSEN
----------------------------------------------------------------
CORPUS_PLAN 5.3 records both halves of this trap. Substituting a colliding name as a bare
token rewrote `wp-content`, `wp-admin` and the string literal `"wp_based"`; substituting
only at segment boundaries missed `php56-<acct>.conf.bak` and `_home_<acct>_public_html_`.
A single width cannot be right for every name, so each identifier gets the widest rule that
its own collisions permit, computed against the stock CMS trees:

  A  substitute ANYWHERE in a token   - the identifier is not a substring of any stock-CMS
                                        token, and is >= 6 characters. This is the tier that
                                        catches `ir-fix<acct>.sh` and `Backup<Acct>0304.zip`,
                                        where the name is glued to the END of a run.
  B  substitute at a LEADING boundary - the identifier occurs inside a stock-CMS token but
                                        never starts one, so a preceding alphanumeric is
                                        enough to tell them apart. Catches `<acct>PUB.zip`
                                        while leaving `mediastorage` alone.
  C  substitute as a WHOLE ALPHABETIC - some stock-CMS token BEGINS with the identifier, so
     RUN                                a leading boundary is not enough. These are the short
                                        account names that read as English words. The
                                        trailing guard is `(?![A-Za-z])`, not
                                        `(?![A-Za-z0-9])`: what makes `animate` a word rather
                                        than the account is the LETTER after the name, while
                                        a digit after it (`<acct>2` - a second IR script for
                                        the same account) still is the account. The
                                        independent check draws the line in the same place
                                        from its own lexical rule rather than from this
                                        table, so neither side can demand what the other
                                        cannot do - 5.3's "a gate that is stricter than the
                                        masker can be is a gate that can never pass".
  D  substitute POSITIONALLY only     - shorter than 3 characters. 5.3's rule verbatim: mask
                                        it only where it can be the account, and have the
                                        gate check exactly that and nothing broader.

Tiers are computed once by `tiers()` and stored in the map, not in this file: which names
collide is a fact about the names, and names live in the map.

THE KEEP-LIST IS NOT OPTIONAL
-----------------------------
Three tokens in this collection contain a customer identifier and are not the customer's:
an attacker-created administrator username, a gambling brand named in a doorway page's
filename, and a third-party tool's hostname recorded as scan evidence. 4.1 keeps attacker
infrastructure deliberately - it is the IOC - and over-matching into it destroys the finding
rather than protecting anyone. They are listed in the map under `keep`, stashed before any
substitution runs and restored afterwards.
"""
import json, os, re, sys

MAP_PATH = os.path.join("trail-data", "incoming", "2026-09-03", "private",
                        "account-mapping.json")

# Public suffixes of two labels, so the owner's label is the third from the right. Not the
# full PSL - only the forms this collection contains. Getting it wrong does not cause a miss,
# it yields a generic label like `com` that matches everywhere, which is worse.
MULTI_SUFFIX = {"com.gr", "co.uk", "org.uk", "com.au", "co.nz", "com.br", "com.tr",
                "edu.gr", "gov.gr", "net.gr", "org.gr", "ac.uk", "co.il", "com.cy"}

# Words that are somebody's subdomain somewhere and nobody's identity anywhere. A subdomain
# label is only identifying in combination with its parent, and treating one as an identifier
# on its own turns this into the substring sweep it exists to replace - `hotel` alone appears
# 299 times in these rows.
GENERIC = {"server", "test", "new", "www", "mail", "web", "dev", "staging", "demo", "old",
           "cdn", "api", "blog", "shop", "admin", "app", "static", "preview", "live"}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def load_map(path=MAP_PATH):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def registrable_label(domain):
    """`a.b.example.com` -> example, `example.com.gr` -> example."""
    parts = [p for p in domain.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def _alternation(strings):
    """Longest first, so a short name can never half-rewrite the longer one it prefixes."""
    return "|".join(re.escape(s) for s in sorted(set(strings), key=len, reverse=True))


def pairs(m):
    """Every real name this incident contains, mapped to its pseudonym.

    Three sources, and the third is the one the first masker did not have:

      * accounts          -> acctNN
      * full domains      -> demoNN.tld
      * registrable label -> the ACCOUNT's pseudonym when an account name and the label are
                             prefix-related IN EITHER DIRECTION, otherwise the domain's
                             pseudonym without the suffix.

    The either-direction test is the whole point. A cPanel account is capped at eight
    characters, so the account is usually a truncation of the company name and the label is
    the full one (`<acct>` vs `<acct>r...`); occasionally a site is the short form of a
    longer account. One direction alone leaves the other class unmasked, and that class is
    exactly what incident-response directories are named after.
    """
    accounts = {a.lower(): p for a, p in m["mapping"].items()}
    out = dict(accounts)
    labels = {}
    for dom, pseudo in m["domains"].items():
        out[dom.lower()] = pseudo
        lab = registrable_label(dom).lower()
        if len(lab) < 3 or lab in GENERIC:
            continue
        labels.setdefault(lab, set()).add(pseudo)

    for lab, pseudos in labels.items():
        owner = None
        for acct, pseudo in accounts.items():
            if acct == lab or lab.startswith(acct) or acct.startswith(lab):
                # Prefer the longest account that is prefix-related. Two accounts on
                # this host differ only by a `_backup_<date>` suffix, so the shorter name
                # is a prefix of the longer one and they must not collapse into one
                # pseudonym. Named generically on purpose: this file is tracked, and
                # pre-push-check.py flagged the earlier version of this very comment for
                # spelling one of the two accounts out.
                if owner is None or len(acct) > len(owner[0]):
                    owner = (acct, pseudo)
        if owner:
            out.setdefault(lab, owner[1])
        elif len(pseudos) == 1:
            out.setdefault(lab, next(iter(pseudos)).replace(".tld", ""))
        # A label shared by several mapped domains with no account behind it cannot be
        # resolved to one pseudonym. Left out on purpose and reported by `unresolved()`:
        # silently picking one would conflate two real sites, which the legacy map's own
        # note calls a worse error than splitting one across two.
    return out


def unresolved(m):
    """Labels this map cannot resolve to a single pseudonym. Reported, never guessed."""
    accounts = {a.lower() for a in m["mapping"]}
    labels = {}
    for dom, pseudo in m["domains"].items():
        lab = registrable_label(dom).lower()
        if len(lab) >= 3 and lab not in GENERIC:
            labels.setdefault(lab, set()).add(pseudo)
    out = {}
    for lab, pseudos in labels.items():
        if len(pseudos) > 1 and not any(lab == a or lab.startswith(a) or a.startswith(lab)
                                        for a in accounts):
            out[lab] = sorted(pseudos)
    return out


def vocabulary(root):
    """Every token of every path under `root`, lowercased. The collision reference.

    Stock CMS trees, deliberately: they contain no customer of ours, so a collision found
    here is a real property of the identifier rather than an artefact of this incident's own
    contaminated paths.
    """
    out = set()
    for base, dirs, files in os.walk(root):
        for name in list(dirs) + list(files):
            for tok in re.split(r"[^A-Za-z0-9]+", name):
                if tok:
                    out.add(tok.lower())
    return out


def tiers(names, vocab):
    """The widest rule each identifier's own collisions permit. See the module docstring."""
    out = {}
    for n in names:
        low = n.lower()
        if len(low) < 3:
            out[n] = "D"
        elif any(t != low and t.startswith(low) for t in vocab):
            out[n] = "C"
        elif any(low in t for t in vocab):
            out[n] = "B"
        else:
            out[n] = "A" if len(low) >= 6 else "B"
    return out


class Masker:
    def __init__(self, m):
        self.m = m
        self.pairs = {k.lower(): v for k, v in pairs(m).items()}
        self.tier = {k.lower(): v for k, v in (m.get("mask_tier") or {}).items()}
        self.keep = [k for k in (m.get("keep") or [])]

        # A full domain carries a dot and is distinctive, so it substitutes anywhere and
        # first: that is what keeps `<label>.<tld>` from being half-rewritten by the bare
        # label rule below, and what catches the urlencoded and log-filename forms.
        domains = [k for k in self.pairs if "." in k and not k.startswith(".")]
        bare = [k for k in self.pairs if k not in domains]

        def of(tier):
            # An identifier with no recorded tier gets the conservative one. A masker that
            # silently widens when the map is stale is the failure this whole file is about.
            return [b for b in bare if self.tier.get(b, "C" if len(b) >= 3 else "D") == tier]

        self.rx_domain = self._rx(domains, "", "")
        self.rx_a = self._rx(of("A"), "", "")
        self.rx_b = self._rx(of("B"), r"(?<![A-Za-z0-9])", "")
        self.rx_c = self._rx(of("C"), r"(?<![A-Za-z0-9])", r"(?![A-Za-z])")
        self.positional = []
        for d in of("D"):
            # 5.3 verbatim: mask it only where it CAN be the account. `/home\d*/`, not
            # `/home/` - the legacy tree's largest account lives at `/home2/`, and a gate or
            # masker narrower than the thing it guards never fires at all.
            e = re.escape(d)
            self.positional += [
                (re.compile(r"(?<=/home/)" + e + r"(?=[/\"'\\\s]|$)", re.I), d),
                (re.compile(r"(?<![A-Za-z0-9])(?<=_home_)" + e + r"(?=_)", re.I), d),
                (re.compile(r"(?<=/home\d/)" + e + r"(?=[/\"'\\\s]|$)", re.I), d),
                (re.compile(r"(?<![A-Za-z0-9])" + e + r"(?=_public_html)", re.I), d),
                (re.compile(r"(?<=php\d\d-)" + e + r"(?=\.conf)", re.I), d),
            ]
        self.keep_rx = self._rx(self.keep, "", "") if self.keep else None

    @staticmethod
    def _rx(items, before, after):
        return (re.compile(before + "(" + _alternation(items) + ")" + after, re.I)
                if items else None)

    def _sub(self, mo):
        return self.pairs[mo.group(1).lower()]

    def mask(self, text):
        """Substitute every mapped identifier. Over-matches by design where a tier allows
        it (5.6): masking a few extra characters of an unrelated token costs nothing,
        leaving a customer name costs everything."""
        if not text or _HEX64.match(text):
            return text
        holes, out = [], text
        if self.keep_rx:                        # protect kept spans first (4.1)
            def stash(mo):
                holes.append(mo.group(0))
                return "\x00%d\x00" % (len(holes) - 1)
            out = self.keep_rx.sub(stash, out)
        for rx in (self.rx_domain, self.rx_a, self.rx_b, self.rx_c):
            if rx:
                out = rx.sub(self._sub, out)
        for rx, name in self.positional:
            out = rx.sub(self.pairs[name], out)
        for i, original in enumerate(holes):
            out = out.replace("\x00%d\x00" % i, original)
        return out

    def collisions(self, vocab):
        """Which identifiers rewrite something they should not, over a real vocabulary.

        The 5.3 check, and the reason the tiers are measured rather than guessed: it reports
        the token, the identifier that hit it and what it would become, so each can be
        judged instead of assumed safe.
        """
        out = []
        for token in sorted(vocab):
            masked = self.mask(token)
            if masked == token:
                continue
            for real in self.pairs:
                if real in token.lower() and real != token.lower():
                    out.append({"token": token, "identifier_len": len(real),
                                "becomes": masked})
                    break
        return out


def mask_row(masker, obj):
    """Every string in the row, keys included.

    5.3's second failure was a field nobody thought of - masking was applied to the path
    because the path was the field the author had in mind, while `prior_corpus.family`
    carried `<acct>-lyxbosa-quarantine` straight through. There is no list of fields here on
    purpose: the row is walked whole, and a new field is covered the day it is added rather
    than the day someone remembers it.
    """
    if isinstance(obj, str):
        return masker.mask(obj)
    if isinstance(obj, list):
        return [mask_row(masker, v) for v in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            mk = masker.mask(k) if isinstance(k, str) else k
            if mk in out:
                raise SystemExit("masking key %r to %r collides with an existing key; "
                                 "refusing to merge two fields into one" % (k, mk))
            out[mk] = mask_row(masker, v)
        return out
    return obj


def _apply(index_path, map_path):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from indexio import read_jsonl, write_jsonl_atomic, index_lock

    masker = Masker(load_map(map_path))
    # The lock is held across the whole read-modify-write and the rows are re-read INSIDE
    # it. Reading first and writing later is how the other session's appends disappear, with
    # every gate still passing - see indexio's docstring.
    with index_lock(index_path):
        rows = read_jsonl(index_path)
        before = len(rows)
        out, changed = [], 0
        for r in rows:
            new = mask_row(masker, r)
            if new != r:
                changed += 1
            out.append(new)
        if len(out) != before:
            raise SystemExit("row count moved %d -> %d; masking must not add or drop rows"
                             % (before, len(out)))
        write_jsonl_atomic(index_path, out)
    print("rows read      : %d" % before)
    print("rows changed   : %d" % changed)
    print("rows written   : %d" % len(out))
    return 0


USAGE = ("usage: incident_mask.py --apply <index.jsonl> [--map <account-mapping.json>]\n"
         "       incident_mask.py --collisions <vocabulary-root> [--map ...]\n"
         "       incident_mask.py --tiers <vocabulary-root> [--map ...]\n"
         "  (this is also a library; see the docstring)")

if __name__ == "__main__":
    argv = sys.argv[1:]
    mp = MAP_PATH
    if "--map" in argv:
        i = argv.index("--map")
        mp = argv[i + 1]
        del argv[i:i + 2]
    if len(argv) == 2 and argv[0] == "--apply":
        sys.exit(_apply(argv[1], mp))
    if len(argv) == 2 and argv[0] == "--collisions":
        mk = Masker(load_map(mp))
        hits = mk.collisions(vocabulary(argv[1]))
        for h in hits:
            print("  %-46s -> %s" % (h["token"][:46], h["becomes"][:46]))
        print("%d token(s) in %s would be rewritten" % (len(hits), argv[1]))
        sys.exit(1 if hits else 0)
    if len(argv) == 2 and argv[0] == "--tiers":
        m = load_map(mp)
        names = [k for k in pairs(m) if "." not in k]
        t = tiers(names, vocabulary(argv[1]))
        print(json.dumps(t, indent=1, sort_keys=True))
        sys.exit(0)
    sys.exit(USAGE)
