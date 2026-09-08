#!/usr/bin/env bash
# Sign SHA256SUMS with the release key, and refuse the release if anything about that is
# not exactly right.
#
#   release-sign.sh sign <dir>      sign <dir>/SHA256SUMS, leaving <dir>/SHA256SUMS.minisig
#   release-sign.sh signing-key     print the key CI signs with
#   release-sign.sh list-trusted    print every key a verifier should accept
#   release-sign.sh --selftest      the controls, both directions, then exit
#                     [--require-minisign]
#
# WHY IT FAILS INSTEAD OF SKIPPING
# ---------------------------------
# A release job that quietly publishes without a signature when signing does not work has
# removed the entire defence at the moment it was needed, and it looks identical to a
# release that worked. So there is no `if: ${{ secrets.X != '' }}`, no `|| true`, and no
# branch anywhere below that leads to "carry on without a signature". Every failure exits
# non-zero, the job stops, and `softprops/action-gh-release` - which runs in a LATER step -
# never runs. That step ordering is the fail-closed guarantee; it is not tidiness, and
# moving the signing step after the release step would silently undo it.
#
# WHAT IT PROVES ON EVERY REAL RELEASE, not only in --selftest
# -------------------------------------------------------------
#   * the signature verifies under the key committed in keys/minisign-trusted.txt. A secret
#     in the repository's secret store that does not match the key consumers have produces
#     a signature nobody can check; this is the only place that can notice.
#   * verification REFUSES a SHA256SUMS with one byte changed. A verify that returns success
#     unconditionally would pass the check above and defend nothing - the same shape as the
#     status check in AGENTS.md that read a 404 body as success and reported ten objects
#     present when all ten were gone.
#
# THE SECRET
# ----------
# It arrives in MINISIGN_SECRET_KEY from a repository secret, is written to a 0600 file in a
# private temp directory outside the workspace, and is removed as soon as minisign has read
# it and again on exit. It is never echoed, never passed as an argument (arguments are
# visible in a process list), and never written anywhere under the checkout - a file in the
# workspace is a file the release could upload.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
KEYRING="${LYXBOSA_KEYRING:-$ROOT/keys/minisign-trusted.txt}"

SUMS="SHA256SUMS"
SIG="SHA256SUMS.minisig"

# minisign's public key form: base64 of "Ed" || key id (8 bytes) || key (32 bytes) = 42
# bytes, which is exactly 56 base64 characters with no padding.
KEY_RE='^RW[A-Za-z0-9+/]{54}$'

PROVISION="Generate a keypair on your own machine and never in CI:

     minisign -G -W -p minisign.pub -s minisign.key

   Put the second line of minisign.pub into keys/minisign-trusted.txt with the role
   'signing', and the whole of minisign.key into the repository secret MINISIGN_SECRET_KEY
   (Settings -> Secrets and variables -> Actions). Keep minisign.key offline; it is the only
   copy. See 'Provisioning the signing key' in docs/RELEASING.md."

die() { echo "error: $*" >&2; exit 1; }

_WORK=""
_cleanup() { [ -n "${_WORK:-}" ] && rm -rf "$_WORK"; return 0; }
trap _cleanup EXIT INT TERM

need_minisign() {
  command -v minisign >/dev/null \
    || die "minisign is not on PATH. In CI it is installed by the step before this one;
   locally, 'sudo apt-get install minisign' or 'brew install minisign'."
}

# ---------------------------------------------------------------------------------------
# The keyring.
# ---------------------------------------------------------------------------------------

# Comment-stripped, blank-stripped records. Nothing here is validated yet.
keyring_records() {
  local f="$1"
  [ -f "$f" ] || die "no keyring at $f"
  sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^[[:space:]]*//' "$f" \
    | grep -v '^$' || true
}

# "<role> <key>" per line, every field validated. A malformed keyring is refused rather than
# read past: the failure mode of reading past it is signing with a key nobody trusts.
keyring_keys() {
  local f="$1" recs line role key rest
  # Asked here, in this function's own shell, and not left to the `die` inside the command
  # substitution below. `set -e` does not apply inside an `if` condition or the subshells it
  # creates, so that die printed its message and execution carried on with an empty string:
  # a missing keyring read as a keyring with no keys in it. Found by a mutation run in which
  # the control for this said "as designed" over the error message that contradicted it.
  [ -f "$f" ] || die "no keyring at $f - the file that says whose signature counts is
   missing, so nothing about this release can be verified."
  recs="$(keyring_records "$f")" || exit 1
  [ -n "$recs" ] || return 0
  while IFS= read -r line; do
    read -r role key rest <<<"$line"
    [ -n "$key" ] && [ -z "$rest" ] \
      || die "malformed record in $f: '$line' (want '<role> <public key>')"
    case "$role" in
      signing|trusted) ;;
      *) die "unknown role '$role' in $f (want 'signing' or 'trusted')" ;;
    esac
    [[ "$key" =~ $KEY_RE ]] \
      || die "not a minisign public key in $f: a ${#key}-character field where 56 were
   expected. A public key is 'RW' plus 54 base64 characters - the second line of a
   minisign.pub file, without the comment line above it."
    printf '%s %s\n' "$role" "$key"
  done <<<"$recs"
}

signing_key() {
  local f="${1:-$KEYRING}" all line n
  all="$(keyring_keys "$f")" || exit 1
  local keys=()
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in "signing "*) keys+=("${line#signing }") ;; esac
  done <<<"$all"
  n=${#keys[@]}
  [ "$n" -ne 0 ] || die "$f lists no key with the role 'signing', so there is nothing to
   sign this release with, and an unsigned release is not published from here.

   $PROVISION"
  [ "$n" -eq 1 ] || die "$f lists $n keys with the role 'signing'. There must be exactly
   one: with two, which key signs a release is decided by line order, and a rotation that
   was half-finished would publish a signature under whichever key happened to be first."
  printf '%s\n' "${keys[0]}"
}

cmd_list_trusted() {
  local all line
  all="$(keyring_keys "$KEYRING")" || exit 1
  [ -n "$all" ] || die "$KEYRING lists no keys at all.

   $PROVISION"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    printf '%s\n' "${line#* }"
  done <<<"$all"
}

# ---------------------------------------------------------------------------------------
# The secret, by shape. Checked before use so that a truncated or wrong-format secret fails
# with a sentence somebody can act on rather than a minisign error about a file it was
# handed. Nothing here prints the value.
# ---------------------------------------------------------------------------------------
#
# A minisign secret key is base64 of 158 bytes:
#   "Ed" | kdf alg (2) | "B2" | salt (32) | opslimit (8) | memlimit (8)
#        | key id (8) | secret key (64) | checksum (32)
# so the key line is exactly 212 base64 characters, and bytes 0-1 and 4-5 are fixed. The kdf
# field is "Sc" for a password-protected key and zero for one generated with -W; both are
# accepted here, because which one is in use is the operator's call and RELEASING.md's.
secret_is_minisign() {
  local f="$1" line dec_len hdr chk
  # \r stripped first: a secret pasted through a Windows editor arrives with CRLF endings
  # and every anchored match below would miss it, which would refuse a key that is perfectly
  # good for a reason nobody could see.
  line="$(tr -d '\r' < "$f" | grep -m1 -E '^[A-Za-z0-9+/]{212}$|^[A-Za-z0-9+/]{211}=$' || true)"
  [ -n "$line" ] || return 1
  dec_len="$(printf '%s' "$line" | base64 -d 2>/dev/null | wc -c)" || return 1
  [ "$dec_len" -eq 158 ] || return 1
  hdr="$(printf '%s' "$line" | base64 -d 2>/dev/null | dd bs=1 count=2 status=none)"
  chk="$(printf '%s' "$line" | base64 -d 2>/dev/null | dd bs=1 skip=4 count=2 status=none)"
  [ "$hdr" = "Ed" ] && [ "$chk" = "B2" ]
}

# One byte, in place, same length. `printf 'X' >>` would also change the file, but a
# mutation that only appends does not test a verifier that reads a fixed prefix.
mutate_one_byte() {
  printf 'X' | dd of="$1" bs=1 seek=7 conv=notrunc status=none
}

# ---------------------------------------------------------------------------------------
# The signing step.
# ---------------------------------------------------------------------------------------
cmd_sign() {
  local dir="${1:-}"
  [ -n "$dir" ] || die "usage: release-sign.sh sign <dir>"
  [ -d "$dir" ] || die "no such directory: $dir"
  local sums="$dir/$SUMS" sig="$dir/$SIG"
  [ -f "$sums" ] || die "no $sums in $dir - release-checksums.sh writes it, and it runs
   before this."
  [ -e "$sig" ] && die "$sig already exists. Refusing to overwrite: a signature already in
   the artifacts directory is either a leftover or something this job did not produce, and
   both are worth stopping for."

  need_minisign
  local key; key="$(signing_key)" || exit 1

  [ -n "${MINISIGN_SECRET_KEY:-}" ] || die "MINISIGN_SECRET_KEY is empty, so this release
   cannot be signed - and an unsigned release is not published from here.

   $PROVISION"

  _WORK="$(mktemp -d)" || exit 1
  chmod 700 "$_WORK"
  ( umask 077; printf '%s\n' "$MINISIGN_SECRET_KEY" > "$_WORK/sk" )
  secret_is_minisign "$_WORK/sk" || die "MINISIGN_SECRET_KEY does not have the shape of a
   minisign secret key: expected a line of 212 base64 characters decoding to 158 bytes
   beginning 'Ed'. Put the WHOLE minisign.key file in the secret, comment line and all -
   a value that lost its newlines or was truncated by a copy-paste lands here."

  # The trusted comment is covered by the signature; the untrusted one is not. What a
  # verifier can rely on therefore goes in -t, and `minisign -V` prints it back.
  local tag="${GITHUB_REF_NAME:-local}"
  printf '%s\n' "${MINISIGN_KEY_PASSWORD:-}" \
    | minisign -S -s "$_WORK/sk" -m "$sums" -x "$sig" \
        -t "LyxBoSa ${tag} ${SUMS} (${GITHUB_REPOSITORY:-LytraX/LyxBoSa})" \
        -c "verify with: minisign -Vm ${SUMS} -P <key from keys/minisign-trusted.txt>" \
    || die "minisign failed to sign $sums. If the key is password-protected, the password
   goes in the repository secret MINISIGN_KEY_PASSWORD; a key generated with -W needs none."
  rm -f "$_WORK/sk"

  # The verification below would also catch this, so no control here can isolate it - it
  # earns its place by producing the message that names what happened instead of a
  # verification failure over a file that is not there.
  [ -f "$sig" ] || die "minisign exited 0 and wrote no $sig"

  # Positive: it verifies under the key that ships in the repository, which is the only key
  # a consumer will have. Not under the secret it was just signed with - that would only
  # prove the secret agrees with itself.
  minisign -V -q -m "$sums" -x "$sig" -P "$key" >/dev/null \
    || { rm -f "$sig"
         die "the signature does not verify under the 'signing' key in $KEYRING. The secret
   in MINISIGN_SECRET_KEY is not the private half of the public key this repository ships,
   so every consumer would fail to verify this release. The signature has been deleted."; }

  # Negative: and it refuses a mutated list. Without this, a verify that returned success
  # unconditionally would pass the line above and defend nothing.
  mkdir -p "$_WORK/neg"
  cp "$sums" "$_WORK/neg/$SUMS"; cp "$sig" "$_WORK/neg/$SIG"
  mutate_one_byte "$_WORK/neg/$SUMS"
  if minisign -V -q -m "$_WORK/neg/$SUMS" -x "$_WORK/neg/$SIG" -P "$key" >/dev/null 2>&1; then
    rm -f "$sig"
    die "verification ACCEPTED a $SUMS with one byte changed. Whatever ran as minisign is
   not checking anything, so the signature it produced is worth nothing. The signature has
   been deleted."
  fi

  _cleanup; _WORK=""
  echo "signed $sums"
  echo "  -> $sig"
  echo "  verifies under $key"
  echo "  and refuses the same file with one byte changed"
}

# ---------------------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------------------
_ok=0
say()  { printf '  %-62s %s\n' "$1" "$2"; }
pass() { say "$1" "correct"; }
fail() { say "$1" "WRONG"; _ok=1; }

# A minisign secret key shaped exactly like a real one and made of nothing: the marker bytes
# followed by zeros. No key material exists here, which is the only acceptable way to have a
# secret key in a repository that has already had to be deleted once over a committed file.
fake_secret() {
  python3 -c 'import base64;print(base64.b64encode(b"Ed"+b"Sc"+b"B2"+bytes(152)).decode())'
}

keyring_with() { printf '%s\n' "$@" > "$1_"; mv "$1_" "$1"; }

# A stand-in with minisign's interface and none of its cryptography. It exists to exercise
# the wiring in this file - which branch runs when signing fails, when verification fails,
# and when verification succeeds on everything - and it proves nothing whatever about
# minisign. The real round trip below needs the real binary.
write_stub() {
  local p="$1"
  mkdir -p "$(dirname "$p")"
  cat > "$p" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
mode="${STUB_MODE:-good}"; op=""; file=""; sigfile=""
while [ $# -gt 0 ]; do
  case "$1" in
    -S) op=sign; shift ;;
    -V) op=verify; shift ;;
    -m) file="$2"; shift 2 ;;
    -x) sigfile="$2"; shift 2 ;;
    -s|-P|-c|-t|-p) shift 2 ;;
    -q|-W|-G) shift ;;
    -v) echo "stub minisign (not minisign)"; exit 0 ;;
    *) shift ;;
  esac
done
[ -n "$sigfile" ] || sigfile="$file.minisig"
h() { sha256sum < "$1" | cut -d' ' -f1; }
case "$op:$mode" in
  sign:sign-fails)   echo "stub: cannot sign" >&2; exit 3 ;;
  sign:sign-silent)  exit 0 ;;
  sign:*)            printf 'STUB %s\n' "$(h "$file")" > "$sigfile" ;;
  verify:verify-fails)     exit 1 ;;
  verify:verify-always-ok) exit 0 ;;
  verify:*)          grep -qx "STUB $(h "$file")" "$sigfile" || exit 1 ;;
esac
STUB
  chmod +x "$p"
}

selftest() {
  local require_minisign=0
  [ "${1:-}" = "--require-minisign" ] && require_minisign=1
  local work kr d out
  work="$(mktemp -d "${TMPDIR:-/tmp}/release-sign-selftest.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  kr="$work/keyring.txt"
  # 56 characters each: RW + 54. Fabricated, and not anybody's key - nothing in the keyring
  # cases verifies a signature, they only ask what the file parses to.
  local K1 K2
  K1="RW$(printf 'A%.0s' $(seq 1 54))"
  K2="RW$(printf 'B%.0s' $(seq 1 54))"
  mkdir -p "$work/empty-bin"

  echo "=== the keyring, both directions ==="
  printf 'signing %s\n' "$K1" > "$kr"
  if [ "$(signing_key "$kr")" = "$K1" ]; then
    pass "one signing key is the key that signs"
  else fail "one signing key is the key that signs"; fi

  { echo "# a comment"; echo; echo "  signing $K1   # in use since v2.3.0"
    echo "trusted $K2 # on its way in"; } > "$kr"
  if [ "$(signing_key "$kr")" = "$K1" ]; then
    pass "comments, blank lines and indentation are ignored"
  else fail "comments, blank lines and indentation are ignored"; fi
  if [ "$( LYXBOSA_KEYRING="$kr" KEYRING="$kr" cmd_list_trusted | tr '\n' ' ')" = "$K1 $K2 " ]; then
    pass "list-trusted prints signing and trusted keys, in file order"
  else fail "list-trusted prints signing and trusted keys, in file order"; fi

  printf 'trusted %s\n' "$K2" > "$kr"
  out="$( signing_key "$kr" 2>&1 )" && { fail "a keyring with no signing key is refused"; } || {
    pass "a keyring with no signing key is refused"
    case "$out" in *"minisign -G"*) pass "...and the refusal says how to provision one" ;;
                   *) fail "...and the refusal says how to provision one" ;; esac; }

  printf 'signing %s\nsigning %s\n' "$K1" "$K2" > "$kr"
  if ( signing_key "$kr" >/dev/null 2>&1 ); then fail "two signing keys are refused"
  else pass "two signing keys are refused"; fi

  printf 'retired %s\n' "$K1" > "$kr"
  if ( signing_key "$kr" >/dev/null 2>&1 ); then fail "an unknown role is refused"
  else pass "an unknown role is refused"; fi

  printf 'signing %s\n' "${K1:0:55}" > "$kr"
  if ( signing_key "$kr" >/dev/null 2>&1 ); then fail "a 55-character key is refused"
  else pass "a 55-character key is refused"; fi

  printf 'signing not-a-key!!\n' > "$kr"
  if ( signing_key "$kr" >/dev/null 2>&1 ); then fail "a key that is not base64 is refused"
  else pass "a key that is not base64 is refused"; fi

  printf 'signing %s extra\n' "$K1" > "$kr"
  if ( signing_key "$kr" >/dev/null 2>&1 ); then fail "a record with a third field is refused"
  else pass "a record with a third field is refused"; fi

  # The keyring this repository actually ships must parse - as far as it goes. It has no
  # signing key yet by design, and that is asserted rather than tolerated, so the day one is
  # added this case says so instead of quietly continuing to pass.
  local rc=0
  ( keyring_keys "$ROOT/keys/minisign-trusted.txt" >/dev/null 2>&1 ) || rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "the keyring this repository ships parses"
  elif ( signing_key "$ROOT/keys/minisign-trusted.txt" >/dev/null 2>&1 ); then
    say "the shipped keyring has a signing key - releases can be signed" "provisioned"
  else
    say "the shipped keyring has no signing key yet, so a release would refuse" "as designed"
  fi

  rm -f "$work/gone.txt"
  out="$( signing_key "$work/gone.txt" 2>&1 )" && fail "a keyring file that is not there is refused" || {
    case "$out" in
      *"no keyring at"*) pass "a keyring file that is not there is refused" ;;
      *) fail "a keyring file that is not there is refused, naming the path" ;;
    esac; }

  echo
  echo "=== the signing step's guards, before anything is signed ==="
  d="$work/art"; mkdir -p "$d"
  printf 'deadbeef  lyxbosa-linux-amd64\n' > "$d/$SUMS"
  printf 'signing %s\n' "$K1" > "$kr"
  # The stub goes on PATH BEFORE the first guard case. Without it these cases run on a
  # machine with no minisign and every one of them passes because `need_minisign` refused
  # first - a control that names one reason and is satisfied by another.
  write_stub "$work/bin/minisign"
  local SK; SK="$(fake_secret)"

  if ( KEYRING="$kr" MINISIGN_SECRET_KEY="" PATH="$work/bin:$PATH" cmd_sign "$d" >/dev/null 2>&1 ); then
    fail "an empty MINISIGN_SECRET_KEY is refused"
  else pass "an empty MINISIGN_SECRET_KEY is refused"; fi
  [ -e "$d/$SIG" ] && { fail "...and nothing was written"; rm -f "$d/$SIG"; } || pass "...and nothing was written"

  # ...and with minisign genuinely absent, the step refuses rather than carrying on. The
  # MESSAGE is what this case asserts: signing would fail anyway when the binary turns out
  # not to exist, so a control that only asked whether the step failed would stay green with
  # the check deleted, and the operator would get "minisign failed to sign" for a missing
  # package. The PATH keeps /usr/bin so that mktemp still works and minisign is the only
  # thing missing.
  out="$( KEYRING="$kr" MINISIGN_SECRET_KEY="$SK" PATH="$work/empty-bin:/usr/bin:/bin" \
          cmd_sign "$d" 2>&1 )" && fail "minisign missing is refused, and the message says so" || {
    case "$out" in
      *"minisign is not on PATH"*) pass "minisign missing is refused, and the message says so" ;;
      *) fail "minisign missing is refused, and the message says so"
         say "  said: $(printf '%s' "$out" | head -1)" "" ;;
    esac; }
  if ( KEYRING="$kr" MINISIGN_SECRET_KEY="$SK" PATH="$work/bin:$PATH" cmd_sign "$work/nodir" >/dev/null 2>&1 ); then
    fail "a directory that does not exist is refused"
  else pass "a directory that does not exist is refused"; fi

  mkdir -p "$work/nosums"
  if ( KEYRING="$kr" MINISIGN_SECRET_KEY="$SK" PATH="$work/bin:$PATH" cmd_sign "$work/nosums" >/dev/null 2>&1 ); then
    fail "a directory with no SHA256SUMS is refused"
  else pass "a directory with no SHA256SUMS is refused"; fi

  printf 'not a signature\n' > "$d/$SIG"
  if ( KEYRING="$kr" MINISIGN_SECRET_KEY="$SK" PATH="$work/bin:$PATH" cmd_sign "$d" >/dev/null 2>&1 ); then
    fail "an existing signature is not overwritten"
  else
    [ "$(cat "$d/$SIG")" = "not a signature" ] \
      && pass "an existing signature is not overwritten" \
      || fail "an existing signature is not overwritten"
  fi
  rm -f "$d/$SIG"

  if ( KEYRING="$kr" MINISIGN_SECRET_KEY="hunter2" PATH="$work/bin:$PATH" cmd_sign "$d" >/dev/null 2>&1 ); then
    fail "a secret that is not a minisign key is refused before signing"
  else pass "a secret that is not a minisign key is refused before signing"; fi
  [ -e "$d/$SIG" ] && { fail "...and nothing was written"; rm -f "$d/$SIG"; } || pass "...and nothing was written"

  echo
  echo "=== the wiring, against a stub that has minisign's interface and no cryptography ==="
  if ( KEYRING="$kr" MINISIGN_SECRET_KEY="$SK" PATH="$work/bin:$PATH" STUB_MODE=good \
       cmd_sign "$d" >/dev/null 2>&1 ) && [ -f "$d/$SIG" ]; then
    pass "a stub that signs and verifies honestly: the step succeeds"
  else fail "a stub that signs and verifies honestly: the step succeeds"; fi
  rm -f "$d/$SIG"

  local mode
  for mode in sign-fails sign-silent verify-fails verify-always-ok; do
    local label
    case "$mode" in
      sign-fails)       label="signing fails" ;;
      sign-silent)      label="signing exits 0 and writes no signature" ;;
      verify-fails)     label="the signature does not verify under the tracked key" ;;
      verify-always-ok) label="verification accepts a mutated SHA256SUMS" ;;
    esac
    if ( KEYRING="$kr" MINISIGN_SECRET_KEY="$SK" PATH="$work/bin:$PATH" STUB_MODE="$mode" \
         cmd_sign "$d" >/dev/null 2>&1 ); then
      fail "$label -> the release fails"
    else
      pass "$label -> the release fails"
    fi
    if [ -e "$d/$SIG" ]; then
      fail "...and no signature is left behind for the release step to publish"
      rm -f "$d/$SIG"
    else
      pass "...and no signature is left behind for the release step to publish"
    fi
  done

  echo
  echo "=== a real minisign, if there is one here ==="
  if command -v minisign >/dev/null; then
    minisign -G -W -p "$work/real.pub" -s "$work/real.key" >/dev/null 2>&1 \
      || { fail "minisign -G generates a keypair"; }
    printf 'signing %s\n' "$(sed -n '2p' "$work/real.pub")" > "$kr"
    if ( KEYRING="$kr" MINISIGN_SECRET_KEY="$(cat "$work/real.key")" cmd_sign "$d" >/dev/null 2>&1 ); then
      pass "a real key signs, and the signature verifies under the tracked public key"
    else fail "a real key signs, and the signature verifies under the tracked public key"; fi
    if [ -f "$d/$SIG" ]; then
      mutate_one_byte "$d/$SUMS"
      if minisign -V -q -m "$d/$SUMS" -x "$d/$SIG" -P "$(sed -n '2p' "$work/real.pub")" >/dev/null 2>&1; then
        fail "...and real verification refuses a SHA256SUMS with one byte changed"
      else pass "...and real verification refuses a SHA256SUMS with one byte changed"; fi
    else
      fail "...and real verification refuses a SHA256SUMS with one byte changed"
    fi
  elif [ "$require_minisign" -eq 1 ]; then
    fail "minisign is on PATH (--require-minisign was given)"
  else
    say "minisign is not installed here, so the two cases above did not run" "NOT EXERCISED"
    say "  the wiring cases ran against the stub; CI runs these with the real binary" ""
  fi

  echo
  if [ $_ok -eq 0 ]; then
    echo "controls: the signing step refuses every way of being wrong that was planted"
  else
    echo "controls: AT LEAST ONE CONTROL FAILED"
  fi
  return $_ok
}

case "${1:-}" in
  sign)         shift; cmd_sign "$@" ;;
  signing-key)  signing_key ;;
  list-trusted) cmd_list_trusted ;;
  --selftest)   shift; selftest "$@" ;;
  *) echo "usage: release-sign.sh sign <dir> | signing-key | list-trusted | --selftest" >&2
     exit 2 ;;
esac
