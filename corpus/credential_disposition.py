#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""What a row says about a credential-shaped literal it keeps, in one place.

WHY THIS EXISTS
---------------
`verify-content-mask.secret_gate()` is a DIFFERENTIAL: it fails on a credential-shaped
literal that is byte-identical before and after masking. A sample that legitimately changed
nothing therefore fails it by construction - every literal it carries is carried over,
because there was no substitution for any of them to survive.

Two published rows are in exactly that state. `pdf-magic-fake-supercache-a` and `-b` each
carry one `quoted-credential` literal, both `changes: 0`, and both were ruled attacker
infrastructure: a backdoor's own access password in its own query-string link, the same
class as the `c2` addresses those rows already keep on purpose under §4.1.

The defect this closes is not that they were kept. It is that NOTHING SAID SO. Neither row
carries the `secret` tag, and `shard-gate.evaluate()` demands a `secret_gate` result only
where that tag is present - so the gate never ran, no result was recorded, and the rule
passed in silence. That is a rule passing for the wrong reason, which is the shape this
repository has now found in eight forms, and the repair is the one §7.2 already reached for
the identifier gates:

    A gate's finding is evidence about the bytes; a tag is a claim about them. Whether the
    evidence is READ must not depend on the claim it might contradict.

So the gate is run, its result is recorded, and the keep becomes an authorised decision
against a recorded finding rather than the absence of one.

WHAT IS RECORDED, AND WHAT IS DELIBERATELY NOT
-----------------------------------------------
A disposition records the SHAPE of the literal and never its value:

    shape                    which `SECRET_SHAPES` pattern matched
    keyword                  the alternation member that fired, from a closed list
    value_length             an integer
    value_character_classes  letters to `a`/`A`, digits to `9`, everything else kept

There is no digest of the value, and that is a decision rather than an omission. A digest's
only job would be to tie the record to the literal in the bytes, and the four fields above
already do that - `matches()` is the tie, and `shard-census.py` re-derives the literals from
the shipped bytes and asserts it there. A truncated digest of a short word is recoverable
from a dictionary in seconds, so it would publish more than the record needs and buy nothing
the shape key does not already give.

The character-class form keeps punctuation literally, which is the convention the round-14
report used for the same purpose. That is what makes a query-string fragment legible as one
without disclosing a character of it.

THE CLOSED VOCABULARY IS THE POINT
-----------------------------------
`DISPOSITIONS` has one member. A second - "masked" - would be a lie, because a masked
literal does not survive to need a disposition, and "ignored" is the state this file exists
to abolish. Keeping the vocabulary closed and single-valued means a row can only ever say
the one thing a human actually decided, and anything else fails `malformed()`.
"""

DISPOSITIONS = ("kept-as-indicator",)

# Every key a disposition must carry. `ground` is the argument a stranger reads; `about`
# names the gate the decision is against, so a disposition can never float free of a
# recorded result the way the two adjudications did before `lift-adjudication.py` moved
# them out of the encoded-layer finding's own key.
REQUIRED = ("shape", "keyword", "value_length", "value_character_classes",
            "disposition", "classification", "ground", "about")

# The keywords `SECRET_SHAPES`' `quoted-credential` alternation can report, restated here so
# a disposition cannot name one the gate cannot produce. Asserted against the live pattern by
# `keep-credential.py --inject` rather than trusted.
KEYWORDS = ("password", "passwd", "pwd", "pass", "api_key", "apikey", "secret")

# The field the row carries them under.
FIELD = "credential_dispositions"


def classes(value):
    """The character-class form of a literal. Letters and digits go, everything else stays.

    Bytes or str, because `secret_literals()` yields bytes and an index row holds text.
    """
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    out = []
    for ch in value:
        if ch.isdigit():
            out.append("9")
        elif ch.isalpha():
            out.append("A" if ch.isupper() else "a")
        else:
            out.append(ch)
    return "".join(out)


def key_of(shape, value):
    """The match key a disposition and a measured literal are compared on."""
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    return (shape, len(value), classes(value))


def key_of_record(d):
    """The same key, taken from a recorded disposition rather than from bytes."""
    return (d.get("shape"), d.get("value_length"), d.get("value_character_classes"))


def malformed(d, recorded_gates=()):
    """Why this disposition cannot be read, or None.

    `recorded_gates` is the set of gate keys the row actually records. A disposition whose
    `about` names a gate the row does not record is describing a decision against nothing,
    which is the free-floating-adjudication defect in its credential-shaped form.
    """
    if not isinstance(d, dict):
        return "not an object"
    missing = [k for k in REQUIRED if d.get(k) in (None, "", [])]
    if missing:
        return "missing %s" % "/".join(missing)
    if d["disposition"] not in DISPOSITIONS:
        return ("disposition %r is not one of %s"
                % (d["disposition"], "/".join(DISPOSITIONS)))
    if not isinstance(d["value_length"], int) or isinstance(d["value_length"], bool):
        return "value_length is not an integer"
    if d["value_length"] != len(d["value_character_classes"]):
        return ("value_length %s disagrees with the %d-character class form"
                % (d["value_length"], len(d["value_character_classes"])))
    if d["keyword"] not in KEYWORDS:
        return "keyword %r is not one the gate can report" % (d["keyword"],)
    for k in ("ground", "classification"):
        if not isinstance(d[k], str) or not d[k].strip():
            return "%s is not a non-empty string" % k
    if recorded_gates and d["about"] not in recorded_gates:
        return ("about names %r, which this row records no result for" % (d["about"],))
    return None


def recorded(masking):
    """The dispositions on one masking block, as a list, whatever the block holds."""
    v = (masking or {}).get(FIELD)
    return v if isinstance(v, list) else []


def matches(masking, literals):
    """(unrecorded, unmatched) for a row against literals measured from its bytes.

    `unrecorded` - a literal in the bytes with no disposition covering it. That is the gap
                   this whole file is about: a credential surviving with nothing saying why.
    `unmatched`  - a disposition covering no literal in the bytes. A record about something
                   that is not there any more, which is a stale keep rather than a leak, and
                   is reported separately because the repair differs.

    Both directions, because a matcher that can only say one of them is the half-check
    AGENTS.md opens with.
    """
    have = {key_of(shape, value) for shape, value in literals}
    said = {key_of_record(d) for d in recorded(masking)}
    return sorted(have - said), sorted(said - have)
