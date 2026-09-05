#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Path masking for the legacy `trail-data/Infected` tree.

Separate from the current-incident masker because the identifiers are different and the
map is different. The map is out of repo (`trail-data/incoming/2026-09-03/private/
infected-tree-mapping.json`); this module is useless without it, which is deliberate -
CORPUS_PLAN 5.3 - and is why the GATE that checks the result asserts a *form* and needs no
map at all.

CORPUS_PLAN 5.3, the two rules that come out of twelve recorded failures:

  * an identifier can appear anywhere inside a token, so this substitutes on a plain
    longest-first alternation rather than on segment prefixes, and covers the
    underscore-encoded `_home_<acct>_` form explicitly;
  * a colliding identifier is masked positionally, and `collisions()` below is what proves
    which identifiers collide, against the vocabulary this tree actually contains, rather
    than against a guess.

`/home\\d*/` and not `/home/`: this tree's largest account lives at `/home2/<acct>/`, which
a `/home/`-only pattern does not see. The gate was widened to match.
"""
import json, os, re

MAP_PATH = os.path.join("trail-data", "incoming", "2026-09-03", "private",
                        "infected-tree-mapping.json")


def load_map(path=MAP_PATH):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _alternation(strings):
    """Longest first, so a short label can never half-rewrite the longer name it prefixes."""
    return "|".join(re.escape(s) for s in sorted(set(strings), key=len, reverse=True))


class Masker:
    def __init__(self, m):
        self.m = m
        self.pairs = {}
        for real, fake in m["sites"].items():
            self.pairs[real] = fake
        for real, fake in m["servers"].items():
            self.pairs[real] = fake
        for real, fake in m["people"].items():
            self.pairs[real] = fake
        for real, fake in m["accounts"].items():
            self.pairs[real] = fake
        for real, fake in m["labels"].items():
            self.pairs.setdefault(real, fake)
        # Keep-list first: a c2 host that happens to contain a customer label must not be
        # rewritten, and an impersonated brand is not ours to mask (4.1).
        self.keep = set(x.lower() for x in m["keep_c2"]) | \
                    set(x.lower() for x in m["impersonated_brands_kept"])
        # Two classes, and the split is the 5.3 positional rule.
        #
        # A full domain carries a dot and is distinctive, so it substitutes ANYWHERE - that
        # is what catches the urlencoded `%2F<client>.gr` form and provider subdomains.
        #
        # A bare label or an account name is not distinctive, so it must START at a
        # non-alphanumeric boundary. Without that, one client label in this map matched
        # inside `UpgradeConsumerSecret.php` and rewrote it mid-word - a real hit found by
        # `collisions()` against the stock CMS vocabulary, and invisible to reading.
        #
        # The boundary is LEADING ONLY, deliberately. 5.6 says to err towards over-matching,
        # and the forms that actually occur are suffixed, not prefixed: `php56-<acct>.conf.bak`,
        # `wp-core-repair-test-<acct>-2026`, `error_log-<client>`. A trailing boundary would
        # miss all of those; a leading one loses only a label glued to the END of an
        # alphanumeric run, which is not a form this tree contains.
        domains = {k: v for k, v in self.pairs.items() if "." in k}
        tokens = {k: v for k, v in self.pairs.items() if "." not in k}
        self.rx_domain = re.compile("(" + _alternation(domains) + ")", re.I) if domains else None
        self.rx_token = re.compile(r"(?<![A-Za-z0-9])(" + _alternation(tokens) + ")",
                                   re.I) if tokens else None
        self.keep_rx = re.compile("(" + _alternation(self.keep) + ")", re.I) if self.keep else None
        self.lookup = {k.lower(): v for k, v in self.pairs.items()}

    def mask(self, text):
        """Substitute every mapped identifier. Over-matches by design (5.6): masking a few
        extra characters of an unrelated token costs nothing, leaving a customer domain
        costs everything."""
        if not text:
            return text
        holes, out = [], text
        if self.keep_rx:                       # protect kept c2 spans first
            def _stash(mo):
                holes.append(mo.group(0))
                return "\x00%d\x00" % (len(holes) - 1)
            out = self.keep_rx.sub(_stash, out)
        sub = lambda mo: self.lookup[mo.group(1).lower()]
        if self.rx_domain:
            out = self.rx_domain.sub(sub, out)
        if self.rx_token:
            out = self.rx_token.sub(sub, out)
        for i, original in enumerate(holes):
            out = out.replace("\x00%d\x00" % i, original)
        return out

    def mask_path(self, rel):
        """A collection-relative path. Also normalises the two encoded account forms."""
        out = self.mask(rel)
        out = re.sub(r"/home\d*/([A-Za-z0-9._-]+)", lambda mo: "/home/" + mo.group(1), out)
        out = re.sub(r"_home\d*_([A-Za-z0-9.-]+)_", lambda mo: "_home_" + mo.group(1) + "_", out)
        return out

    def collisions(self, vocabulary):
        """Which identifiers rewrite something they should not, over a real vocabulary.

        This is the 5.3 check: `wp` inside `wp_based`, one account's name inside
        `ir-malware-samples`. It reports the token, the identifier that hit it, and what it
        would become, so each can be judged rather than assumed safe.

        The attribution loop used to require `real.lower() != token.lower()`, which silently
        dropped the strongest collision there is - a token that IS an identifier, i.e. a name
        that is also an ordinary word this vocabulary uses. `mask()` rewrites it and the
        report said nothing, so the check could not fail in the one direction that matters
        most. 5.3's tenth recorded failure, found in `incident_mask.py` and identical here.
        """
        out = []
        for token in sorted(set(vocabulary)):
            masked = self.mask(token)
            if masked == token:
                continue
            for real in sorted(self.pairs, key=len, reverse=True):
                if real.lower() in token.lower():
                    out.append({"token": token, "identifier_len": len(real),
                                "exact": real.lower() == token.lower(), "becomes": masked})
                    break
            else:
                # Rewritten with no identifier inside it. Not attributable, so reported as
                # itself: an unexplained rewrite is a finding, not something to drop.
                out.append({"token": token, "identifier_len": None, "exact": False,
                            "becomes": masked})
        return out
