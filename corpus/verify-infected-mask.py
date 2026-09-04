#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent check that no client identifier survives in the rows of either half.

CORPUS_PLAN 5.3: "Verification must not share the masker's regexes. A self-check built from
the same patterns passes while being wrong." So this shares nothing with `infected_mask.py`
or `incident_mask.py`: **no identifier is ever compiled into a regex here**. Identifiers are
compared with `str` operations only - `in`, `startswith`, slicing - over a vocabulary this
file enumerates for itself. The only regexes below describe SLOTS (`/home<digits>/<x>/` and
friends), and a slot pattern captures an arbitrary value and then asks a question about it;
it does not encode which names are real, which is the part that must not be shared.

It is also NOT a substring sweep, and that is the second half of the same lesson. Three
sweeps failed on this corpus in one day: `wp` matched 52,103 rows because of `wp-content`,
`global` matched 227 because of Elementor's global-widget files, and a third matched the
very sentence that was describing it as an example, because one client's label is a
substring of a stock Magento class name. A sweep whose output is thousands of hits that must
each be explained away is a sweep nobody finishes. (That third one is also why no example
here is spelled out: 5.3's own record contains a commit titled "scrub three client names"
that left a fourth in the paragraph explaining the scrub.)

What it does instead is POSITIVE and finite:

  1. enumerate every distinct path segment the rows actually store, from every string value
     AND every dict key in every row - not just the field someone remembered to mask
     (5.3 failure 2, which is how `prior_corpus.family` kept carrying names);
  2. ask, for each segment, whether a known identifier occurs inside it;
  3. ask, for values sitting in an ACCOUNT-SHAPED SLOT only, the reverse question: is this
     value a truncation of a known identifier?

WHY STEP 3 IS POSITIONAL AND STEP 2 IS NOT
------------------------------------------
An identifier can appear in a token in two directions, and a check that tests one of them
certifies nothing about the other. Both directions really occur here:

  * the recorded name is SHORTER than what the directory used - an account `<a>` appearing
    as `<a>x-backup-component-validation-<8 digits>-<6 digits>`. Step 2 catches this: the
    name is inside the segment. 2,402 occurrences of one name survived a year of collection
    because the previous check asked `segment.startswith(name + "-")`, which is false the
    moment the segment continues with a letter.
  * the recorded name is LONGER than what the directory used - an account `<abc...>`
    appearing as `<ab>-safe-repair-...`. Step 2 cannot see this at all: the segment contains
    no identifier, it merely starts one.

Step 3 has to be positional because unrestricted it is the sweep this file exists to
replace. Over these rows, "is this segment a prefix of a client name" fires on `global`
(243 hits, Elementor), `villa`, `euro`, `inter`, `cloud` and `paint` - all coincidences, and
a check nobody finishes is a check nobody runs. In an account slot the same question has a
small, exact answer set, because the only things that legitimately sit there are pseudonyms.

`--show-vocabulary` prints the segment vocabulary itself, which is the artefact worth
reading: it is the complete list of what these rows say, and it is short enough to read.
`--inject` proves the check can fail, by feeding it each leaked form one at a time.
"""
import json, os, re, sys, collections, argparse

PRIVATE = os.path.join("trail-data", "incoming", "2026-09-03", "private")
LEGACY_MAP = os.path.join(PRIVATE, "infected-tree-mapping.json")
INCIDENT_MAP = os.path.join(PRIVATE, "account-mapping.json")
SEPARATORS = "/.-_@!:, \\'\"()[]{}=?&+"


# Words that are somebody's subdomain somewhere and nobody's identity anywhere. Without
# this the check drowns in exactly the noise it exists to avoid: run against the
# current-incident map, whose `domains` include several `server.*` and `test.*` subdomains,
# a first version reported `server`, `test` and `new` as leaks.
GENERIC = {"server", "test", "new", "www", "mail", "web", "dev", "staging", "demo", "old",
           "cdn", "api", "blog", "shop", "admin", "app", "static", "preview", "live"}


# Public suffixes that are TWO labels, so the owner's name is the third from the right.
# Not the full PSL - just the forms this collection actually contains. Without it
# a `<name>.com.gr` domain yields the label `com`, which is generic, matches everywhere and
# turns the check back into the substring sweep it exists to replace.
MULTI_SUFFIX = {"com.gr", "co.uk", "org.uk", "com.au", "co.nz", "com.br", "com.tr",
                "edu.gr", "gov.gr", "net.gr", "org.gr", "ac.uk", "co.il", "com.cy"}


# The slots in which a value can only ever be an account or a site. Each captures an
# arbitrary run and asks a question about it afterwards; none of them knows a real name.
# `/home\d*/` and not `/home/`: the legacy tree's largest account lives at `/home2/`, and a
# check narrower than the thing it guards never fires at all.
SLOTS = [
    ("/home*/<x>/",       re.compile(r"/home\d*/([A-Za-z0-9][A-Za-z0-9._-]*)")),
    ("_home*_<x>_",       re.compile(r"_home\d*_([A-Za-z0-9][A-Za-z0-9.-]*)_")),
    ("<x>_public_html",   re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9][A-Za-z0-9.-]*)_public_html")),
    ("phpNN-<x>.conf",    re.compile(r"php\d+-([A-Za-z0-9][A-Za-z0-9.-]*)\.conf")),
    # The incident-response directory shape. Its leading token is an account name in every
    # case where it is not an operation verb, and that is exactly the discriminator the
    # published gate cannot make - see promote-gate.py.
    ("IR-dir <x>-...-N-N", re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9][A-Za-z0-9_]*)-"
                                      r"[A-Za-z0-9_.-]*?\d{8}-\d{6}")),
]
PSEUDONYM = re.compile(r"^(acct\d+|site\d+|srv\d+|demo\d+(\.tld)?|person\d+)$")
TRUNCATION_FLOOR = 4


def registrable_label(domain):
    """`example.gr` -> example, `a.b.example.com` -> example,
    `example.com.gr` -> example.

    The label that names the owner is the one before the public suffix, and the public
    suffix is not always one label. Getting this wrong does not produce a miss, it produces
    a generic token that matches everything - which is worse, because the output stops being
    readable and the check stops being run.
    """
    parts = [p for p in domain.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def identifiers(m):
    """Every real-world name a map contains, as plain strings.

    Two map schemas, one question. The legacy tree's map (`infected-tree-mapping.json`)
    names sites, servers, people and masked directories separately; the current incident's
    (`account-mapping.json`) has accounts and domains. Reading both here is what lets one
    tool cover both trees - the alternative was a second copy of this file with a different
    constant at the top, and a second copy is a second thing to forget to fix.

    Each domain contributes its registrable label as well as the full string, because the
    bare label identifies the customer as surely as the full domain does - and the bare
    label is the form incident-response directories are actually named after.
    """
    out = set()
    if "mapping" in m:                                  # current-incident schema
        out |= set(m["mapping"])
        for d in m.get("domains", {}):
            out.add(d)
            out.add(registrable_label(d))
    else:                                               # legacy Infected-tree schema
        for d in list(m.get("sites", {})) + list(m.get("servers", {})) + \
                 list(m.get("dirs_masked", {})):
            out.add(d)
            out.add(registrable_label(d))
        out |= set(m.get("accounts", {}))
        out |= set(m.get("people", {}))
        out |= set(m.get("labels", {}))
    return {x.lower() for x in out if len(x) >= 3 and x.lower() not in GENERIC}


def keep_tokens(m):
    """Attacker infrastructure and impersonated brands, kept deliberately (4.1).

    An identifier that lives inside one of these is not a leak: rewriting an attacker's
    admin username or a phishing kit's target brand destroys the IOC, which is the finding.
    """
    keep = set()
    for field in ("keep_c2", "impersonated_brands_kept", "keep"):
        keep |= {x.lower() for x in m.get(field, [])}
    return keep


def strings_in(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            for s in strings_in(v):
                yield s
    elif isinstance(obj, list):
        for v in obj:
            for s in strings_in(v):
                yield s


def segments_of(text):
    """Split on every separator. No regex: the point is not to reuse the masker's idea of
    what a boundary is."""
    cur, out = [], []
    for ch in text:
        if ch in SEPARATORS:
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


LONG_ENOUGH_TO_BE_ONLY_A_NAME = 6


def _is_a_leak(segment, ident, at):
    """Does `ident` occurring at `at` inside `segment` identify a customer?

    Containment rather than prefix, which is affordable ONLY because these identifiers are
    client names rather than words. That is the difference from the sweep that reported `wp`
    in 52,103 rows: `wp` is a CMS prefix, a client label is a company. Two controls depend on
    it: a `%2F<client>.gr` reference in a cached URL splits to the segment `2f<client>`,
    which does not BEGIN with the label, and `Backup<Acct>0304` continues with a digit, so a
    trailing-boundary rule cannot see it either. Both are forms the masker handles, and a
    check that cannot see a form the masker handles cannot certify the masker.

    But containment alone is only affordable for names long enough to be nothing else. Six
    characters is where that stops being true here: the maps contain five account names of
    three to five characters that are also ordinary English fragments, and unrestricted
    containment reports `manual` 49,292 times for one of them and `same` 31,089 times for
    another. Those are coincidences, and this file exists because a check whose output is
    thousands of coincidences is a check nobody finishes.

    So a short identifier counts only as a whole ALPHABETIC run - no letter on either side.
    That keeps `manual`, `animate`, `watermark`, `progress`, `mediaselect`, `pelican` and
    `underwater` silent while still catching `<acct>` alone, `<acct>2` and `php56-<acct>`.
    It is a lexical rule, derived here rather than read from the masker's table, and it lands
    on the same boundary the masker uses - which is the point: neither side may demand what
    the other cannot do.
    """
    rest = segment[at + len(ident):]
    if len(ident) >= LONG_ENOUGH_TO_BE_ONLY_A_NAME:
        return True
    before = segment[at - 1] if at else ""
    return not before.isalpha() and not (rest and rest[0].isalpha())


def check(rows, ids, keep):
    """Both directions. Returns (containment hits, truncation hits, vocabulary)."""
    keep_segments = set()
    for k in keep:
        keep_segments |= {s.lower() for s in segments_of(k)}

    vocab = collections.Counter()
    where = {}
    for r in rows:
        sha = r.get("sha256", "?")
        for s in strings_in(r):
            for seg in segments_of(s):
                vocab[seg] += 1
                where.setdefault(seg, sha)

    contained = []
    for seg in sorted(vocab):
        low = seg.lower()
        if low in keep_segments:
            continue
        for ident in sorted(ids, key=len, reverse=True):
            at = low.find(ident)
            if at < 0 or not _is_a_leak(low, ident, at):
                continue
            pos = "exact" if low == ident else ("begins" if at == 0 else "contains")
            contained.append((seg, ident, vocab[seg], where[seg], pos))
            break

    # Direction 2 - truncation, in an account slot only. See the module docstring for why
    # this one is positional and direction 1 is not.
    truncated = []
    seen = set()
    for r in rows:
        sha = r.get("sha256", "?")
        for s in strings_in(r):
            for label, rx in SLOTS:
                for value in rx.findall(s):
                    low = value.lower()
                    if PSEUDONYM.match(low) or len(low) < TRUNCATION_FLOOR:
                        continue
                    if low in keep_segments:
                        continue
                    for ident in sorted(ids, key=len, reverse=True):
                        if ident != low and ident.startswith(low):
                            key = (value, label, ident)
                            if key not in seen:
                                seen.add(key)
                                truncated.append((value, label, ident, sha))
                            break
    return contained, truncated, vocab


# The forms that have actually leaked out of this corpus, one per line, with `%s` where the
# identifier goes. A check is only worth running if it can fail, and this is how that is
# demonstrated rather than asserted: each is injected on its own and must be caught.
INJECTIONS = [
    ("account as a whole path segment",     "/home/%s/public_html/index.php"),
    ("account under /home2 (legacy tree)",  "/home2/%s/public_html/index.php"),
    ("name LONGER than the record",         "/root/INCIDENT/%sx-backup-component-"
                                            "validation-20260828-234000/staged/x.php"),
    ("name SHORTER than the record",        "TRUNCATE"),
    ("glued to the end of a run",           "/home/acct01/Backup%s0304.zip"),
    ("underscore-encoded quarantine name",  "/root/q/_home_%s_public_html_wp-admin.php"),
    ("mid-token with a suffix",             "/root/q/php56-%s.conf.bak"),
    ("urlencoded domain reference",         "/cache/https%%3A%%2F%%2F%s.gr%%2Findex"),
    ("free prose, not a path",              "seen across three accounts (%s and two others)"),
    ("a field nobody thought of",           "FIELD"),
]


# Forms that must NOT fire. A check that catches everything proves nothing about a corpus
# that contains `manual` 49,292 times, so the negative half is as load-bearing as the
# positive one - 5.3's ninth failure was a test loosened until it agreed, and the repair
# there was controls in both directions before the answer was trusted.
NEGATIVE = [
    ("ordinary word starting a short name", "/x/wp-content/plugins/%(short)sal-import.php"),
    ("short name inside a longer word",     "/x/media%(short)select.php"),
    ("short name ending a longer word",     "/x/under%(short)s.php"),
    ("a pseudonym, which is the point",     "/home/acct01/public_html/index.php"),
]


def inject(ids, keep):
    """Feed each leaked form back in on its own and confirm the check's verdict.

    A check is only worth running if it can fail, and this is how that is demonstrated
    rather than asserted. Two identifiers are used: the longest, which containment alone
    must catch, and a short one, which only the whole-alphabetic-run rule can catch without
    also catching English.
    """
    longest = max((i for i in ids if len(i) >= LONG_ENOUGH_TO_BE_ONLY_A_NAME),
                  key=len, default=None)
    short = min((i for i in ids if len(i) < LONG_ENOUGH_TO_BE_ONLY_A_NAME),
                key=len, default=None)
    if longest is None:
        print("no identifier long enough to inject with"); return 1
    base = {"sha256": "0" * 64, "size": 1}
    failures = []

    def verdict(row):
        c, t, _ = check([row], ids, keep)
        return bool(c or t)

    for name, form in INJECTIONS:
        row = dict(base)
        if form == "TRUNCATE":
            # The direction that has no containment signal at all: a real account recorded
            # as <abcdefgh> written in the directory as <abcd>. Only the positional
            # truncation test can see it, and only because the slot says what it is.
            row["origin"] = {"path": "/home/%s/public_html/x.php" % longest[:len(longest) - 3]}
        elif form == "FIELD":
            row["a_field_added_next_week"] = {longest + "-quarantine": "whatever"}
        else:
            row["origin"] = {"path": form % longest}
        ok = verdict(row)
        print("   +  %-38s %s" % (name, "caught" if ok else "MISSED"))
        if not ok:
            failures.append(name)

    if short:
        for name, form in (("short name alone in a slot", "/home/%(short)s/public_html/x"),
                           ("short name with a trailing digit", "/root/ir/ir-%(short)s2.sh"),
                           ("short name in a config filename", "/root/q/php56-%(short)s.conf")):
            row = dict(base)
            row["origin"] = {"path": form % {"short": short}}
            ok = verdict(row)
            print("   +  %-38s %s" % (name, "caught" if ok else "MISSED"))
            if not ok:
                failures.append(name)
        for name, form in NEGATIVE:
            row = dict(base)
            row["origin"] = {"path": form % {"short": short}}
            ok = verdict(row)
            print("   -  %-38s %s" % (name, "FIRED (false positive)" if ok else "silent"))
            if ok:
                failures.append(name + " (should not fire)")

    print()
    if failures:
        print("FAIL: the check got %d of its own controls wrong: %s"
              % (len(failures), ", ".join(failures)))
        return 1
    print("every known leak form is caught and every control stays silent; "
          "the check can fail, and does not fire on English")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rows", help="jsonl of the rows to check")
    ap.add_argument("--map", default=INCIDENT_MAP,
                    help="pseudonym map, either schema. Default is the "
                         "current-incident map; the legacy tree's is %s. Pass it "
                         "explicitly: one tool, two trees, and which tree a row came from "
                         "is not something the row records." % LEGACY_MAP)
    ap.add_argument("--show-vocabulary", action="store_true")
    ap.add_argument("--inject", action="store_true",
                    help="prove the check can fail, then exit")
    a = ap.parse_args()

    with open(a.map, encoding="utf-8") as fh:
        m = json.load(fh)
    ids = identifiers(m)
    keep = keep_tokens(m)

    print("map                          : %s" % a.map)
    print("client identifiers to look for: %d" % len(ids))

    if a.inject:
        print()
        return inject(ids, keep)

    rows = [json.loads(l) for l in open(a.rows, encoding="utf-8") if l.strip()]
    contained, truncated, vocab = check(rows, ids, keep)
    print("rows checked                 : %d" % len(rows))
    print("distinct path segments stored: %d" % len(vocab))

    print()
    if contained:
        print("=== SEGMENTS CARRYING A CLIENT NAME: %d ===" % len(contained))
        for seg, ident, n, sha, pos in contained:
            print("   %-40s %-8s %-22s n=%-5d %s" % (seg[:40], pos, ident, n, sha[:12]))
    if truncated:
        print("=== ACCOUNT SLOTS HOLDING A TRUNCATED CLIENT NAME: %d ===" % len(truncated))
        for value, label, ident, sha in truncated:
            print("   %-30s in %-20s truncates %-22s %s"
                  % (value[:30], label, ident, sha[:12]))
    if contained or truncated:
        print()
        print("FAIL: a client identifier survives in the stored rows.")
        return 1

    print("=== no stored segment carries a client identifier, in either direction ===")
    print("PASS")
    if a.show_vocabulary:
        print()
        print("=== the segment vocabulary these rows store (%d) ===" % len(vocab))
        for seg, n in vocab.most_common():
            print("   %-52s %d" % (seg[:52], n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
