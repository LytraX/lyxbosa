#!/bin/sh
# Run a command until it succeeds, up to a fixed number of attempts.
#
#   retry <command> [args...]     run it, up to $RETRY_ATTEMPTS times
#   retry --selftest              the controls, both directions
#
# WHY A SCRIPT AND NOT A LOOP IN THE DOCKERFILE
# --------------------------------------------
# Two images need this and a loop written into each is two loops that agree today. It is
# also the half that cannot be proved by reading: a retry that never retried and a retry
# that gave up too early both look exactly like a build that passed. So it is a file, both
# Dockerfiles copy it, and --selftest drives it against commands that fail a known number
# of times and asserts the attempt count.
#
# WHAT IT IS FOR
# --------------
# Fetching packages over a network that is not this repository's. On 2026-09-12 both glibc
# build jobs failed thirteen seconds in because every AlmaLinux mirror answered 404 for the
# BaseOS repodata that dnf had just been told to fetch; eleven minutes earlier the same
# source tree had passed, and a plain re-run passed again. Nothing about that was the
# build's fault and nothing in it was worth failing a release over.
#
# It does NOT paper over a real refusal. A command that fails for its own reasons fails
# $RETRY_ATTEMPTS times and this exits with its status, so the log carries every attempt
# and the exit code is the command's own.
set -eu

RETRY_ATTEMPTS="${RETRY_ATTEMPTS:-4}"
RETRY_DELAY="${RETRY_DELAY:-5}"

retry() {
    attempt=1
    while : ; do
        # The else branch is not tidiness. After an `if cmd; then ... fi` whose condition
        # failed, $? is the status of the IF STATEMENT, which is 0 - so reading it below
        # the block returned "gave up" as success, and --selftest said so on the first run
        # of this file. The condition's own status is readable only here.
        if "$@"; then
            [ "$attempt" -gt 1 ] && echo "retry: succeeded on attempt ${attempt}" >&2
            return 0
        else
            status=$?
        fi
        if [ "$attempt" -ge "$RETRY_ATTEMPTS" ]; then
            echo "retry: giving up after ${attempt} attempts, last exit ${status}: $*" >&2
            return "$status"
        fi
        echo "retry: attempt ${attempt} of ${RETRY_ATTEMPTS} exited ${status}, waiting ${RETRY_DELAY}s: $*" >&2
        sleep "$RETRY_DELAY"
        attempt=$((attempt + 1))
    done
}

# ---------------------------------------------------------------- selftest

selftest() {
    tmp="$(mktemp -d)"
    n=0
    bad=0

    # A command that fails its first N invocations and then succeeds, counting every one
    # into a file so the assertion is about attempts made and not merely about the verdict.
    cat > "$tmp/flaky" <<'EOF'
#!/bin/sh
count_file="$1"; fail_until="$2"
n=$(cat "$count_file" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$count_file"
[ "$n" -gt "$fail_until" ]
EOF
    chmod +x "$tmp/flaky"

    check() {  # check <expectation:ok|no> <description> <command...>
        want="$1"; desc="$2"; shift 2
        n=$((n + 1))
        if "$@" >/dev/null 2>&1; then rc=ok; else rc=no; fi
        if [ "$rc" = "$want" ]; then
            printf '  ok    %-58s (said %s)\n' "$desc" "$rc"
        else
            printf '  FAIL  %-58s (said %s, wanted %s)\n' "$desc" "$rc" "$want"
            bad=$((bad + 1))
        fi
    }

    attempts_were() {  # attempts_were <file> <expected>
        [ "$(cat "$1" 2>/dev/null || echo 0)" = "$2" ]
    }

    echo "retry.sh --selftest"
    echo
    echo "the verdict, both directions:"
    RETRY_DELAY=0 RETRY_ATTEMPTS=4 check ok "a command that succeeds first time succeeds" \
        retry "$tmp/flaky" "$tmp/c1" 0
    RETRY_DELAY=0 RETRY_ATTEMPTS=4 check ok "a command that fails twice then succeeds succeeds" \
        retry "$tmp/flaky" "$tmp/c2" 2
    RETRY_DELAY=0 RETRY_ATTEMPTS=4 check no "a command that always fails is NOT reported ok" \
        retry "$tmp/flaky" "$tmp/c3" 99

    echo
    echo "the attempts actually made, which is what a verdict alone cannot show:"
    check ok "the one that succeeded first time ran once, not four times" \
        attempts_were "$tmp/c1" 1
    check ok "the one that failed twice ran exactly three times" \
        attempts_were "$tmp/c2" 3
    check ok "the one that always fails ran exactly RETRY_ATTEMPTS times" \
        attempts_were "$tmp/c3" 4
    check no "three attempts is not four - a miscount is caught" \
        attempts_were "$tmp/c3" 3

    echo
    echo "the exit status handed back is the command's own, not a fixed 1:"
    RETRY_DELAY=0 RETRY_ATTEMPTS=2 retry sh -c 'exit 7' >/dev/null 2>&1 || got=$?
    check ok "a command exiting 7 makes retry exit 7" test "${got:-0}" = 7

    echo
    echo "RETRY_ATTEMPTS is read rather than hardcoded:"
    RETRY_DELAY=0 RETRY_ATTEMPTS=2 check no "two attempts configured means two, then give up" \
        retry "$tmp/flaky" "$tmp/c4" 99
    check ok "and it ran exactly twice" attempts_were "$tmp/c4" 2

    rm -rf "$tmp"
    echo
    if [ "$bad" -eq 0 ]; then
        echo "$n cases, all ok"
        return 0
    fi
    echo "$n cases, $bad NOT ok"
    return 1
}

case "${1:-}" in
    --selftest) selftest ;;
    "") echo "usage: retry.sh <command> [args...]   |   retry.sh --selftest" >&2; exit 2 ;;
    *) retry "$@" ;;
esac
