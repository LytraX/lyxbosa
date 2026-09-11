#!/usr/bin/env bash
# Controls for scripts/install.sh and scripts/install.ps1.
#
#   corpus/install-scripts.sh --selftest    every case, then exit
#
# WHY IT LIVES IN corpus/ WHEN WHAT IT TESTS DOES NOT
# ----------------------------------------------------
# Because this is where something runs it. `corpus/control-suites.py` discovers every
# `corpus/*.py` and `corpus/*.sh` that dispatches on `--inject` or `--selftest`, and it is
# the fifth of the five commands AGENTS.md requires before a round is reported green. A
# control suite anywhere else in this tree is run when somebody remembers, which is the
# arrangement that left three shell suites unwatched until a runner was written to find
# them. The install scripts are the first thing a stranger runs, as root, on a host they
# are in the middle of an incident on; they are the last place to accept a control nobody
# executes.
#
# WHAT IT ASSERTS, IN FOUR KINDS
# -------------------------------
#   AGREEMENT   The scripts carry three lists they cannot read at run time - the prefixes a
#               package manager owns, the glibc floor and paths the standard build needs,
#               and the minisign keys. Each is a copy, because a script fetched on its own
#               has no repository to read. What keeps a copy from drifting is this file:
#               every one is PARSED out of the source of truth and compared, so a rotation
#               or a raised build floor that forgets the installer fails a pre-report
#               command rather than a release.
#   REFUSALS    Asserted by calling the functions, including the three that a developer's
#               machine cannot otherwise show: a host with no loader, one whose glibc is
#               too old, one whose C library cannot be read.
#   DECISION    The build choice as a truth table, because "an existing portable install is
#               not moved" is a rule with no observable consequence on a host that has
#               neither build installed.
#   END TO END  A fabricated release in a local directory, signed with a throwaway key, so
#               that a real verification is watched accepting a good release AND refusing a
#               mutated one. A verification nobody has seen refuse anything is not a
#               verification.
#
# WHAT IT CANNOT ASSERT
# ----------------------
# install.ps1's behaviour. There is no PowerShell on this machine, so everything below
# about it is a claim about its TEXT, and it says so in each label. Its behaviour is
# exercised by `install.ps1 -SelfTest` in the `test-windows` job, which is the only place
# in this project that can run it.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

INSTALL_SH="$ROOT/scripts/install.sh"
INSTALL_PS1="$ROOT/scripts/install.ps1"
INSTALL_PATH_CPP="$ROOT/src-lib/cpp/update/InstallPath.cpp"
BUILD_IDENTITY_CPP="$ROOT/src-lib/cpp/update/BuildIdentity.cpp"
KEYRING="$ROOT/keys/minisign-trusted.txt"
WORKFLOW="$ROOT/.github/workflows/build.yml"
RELEASE_CHECKSUMS="$ROOT/.github/scripts/release-checksums.sh"

_ok=0
_cases=0
say()  { printf '  %-66s %s\n' "$1" "$2"; }
pass() { _cases=$((_cases + 1)); say "$1" "correct"; }
fail() { _cases=$((_cases + 1)); say "$1" "WRONG"; _ok=1; }
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1"; printf '      want: %s\n      got:  %s\n' "$3" "$2"; fi; }
ok()   { if "${@:2}" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi; }
nope() { if "${@:2}" >/dev/null 2>&1; then fail "$1"; else pass "$1"; fi; }

# ---------------------------------------------------------------------------------------
# The sources of truth, parsed rather than restated.
# ---------------------------------------------------------------------------------------

# The twelve entries of kOwned in InstallPath.cpp, first string of each row.
cpp_owned_prefixes() {
  sed -n '/kOwned{{/,/}};/p' "$INSTALL_PATH_CPP" \
    | sed -n 's/^[[:space:]]*{"\([^"]*\)".*/\1/p'
}

cpp_glibc_floor() {
  sed -n 's/.*kStandardBuildGlibcMinor = \([0-9][0-9]*\).*/\1/p' "$BUILD_IDENTITY_CPP" | head -1
}

# Two, in source order: x86_64 then aarch64.
cpp_loader_paths() {
  sed -n 's/.*kLoaderPath = "\([^"]*\)".*/\1/p' "$BUILD_IDENTITY_CPP"
}

# Eight, in source order: the x86_64 four then the aarch64 four.
cpp_libc_paths() {
  sed -n '/kLibcPaths{/,/};/p' "$BUILD_IDENTITY_CPP" \
    | sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p'
}

# The count the release job asserts over its artifacts directory.
workflow_expect() {
  sed -n 's/.*release-checksums.sh write artifacts --expect \([0-9][0-9]*\).*/\1/p' \
      "$WORKFLOW" | head -1
}

# The names release-checksums.sh's own fixture says a release publishes. That file's controls
# assert the fixture is exactly right, so it is the nearest thing to a machine-readable
# manifest this repository has - and asking it, rather than counting to eight here, is what
# stops a third place from holding the number.
fixture_names() {
  sed -n '/^FIXTURE_NAMES=(/,/)$/p' "$RELEASE_CHECKSUMS" \
    | sed -e 's/FIXTURE_NAMES=(//' -e 's/)//' -e 's/\\$//' \
    | tr -s ' \t' '\n' | grep .
}

# The line number of a step's name in the workflow, so that "before" can be asserted rather
# than assumed.
workflow_step_line() {
  grep -n -- "- name: $1" "$WORKFLOW" | head -1 | cut -d: -f1
}

keyring_keys() {
  sed -e 's/#.*//' "$KEYRING" | awk 'NF == 2 { print $2 }'
}

# The keys install.ps1 ships with, read off the one line that declares them. Matched by the
# shape minisign's public keys have - RW and 54 more base64 characters - rather than by
# unpicking PowerShell array syntax.
ps1_keys() {
  sed -n '/^\$BuiltinKeys = @(/p' "$INSTALL_PS1" | grep -o 'RW[A-Za-z0-9+/]\{54\}'
}

# ---------------------------------------------------------------------------------------
# Fabricated hosts and fabricated releases.
# ---------------------------------------------------------------------------------------

# A file the glibc reader will accept as an ELF, carrying the version names it is given.
#
# `tr -c '[:print:]' '\n'` turns EVERY non-printable byte into a line break, so a newline
# separates these names exactly as a NUL separates the entries of a real .dynstr - which is
# what makes a text file a faithful stand-in for the string table the C++ reader walks.
make_libc() {
  local file="$1"; shift
  { printf '\177ELF\n'; printf '%s\n' "$@"; } > "$file"
}

# The six binaries a release publishes, as scripts that answer --version the way the real
# ones do, plus install.sh itself, hashed into SHA256SUMS and signed.
make_release() {
  local dir="$1" arch name
  mkdir -p "$dir"
  for arch in amd64 arm64; do
    for name in "lyxbosa-linux-$arch" "lyxbosa-linux-$arch-portable"; do
      case "$name" in
        *-portable) printf '#!/bin/sh\necho "9.9.9 (portable build, %s)"\n' "$name" > "$dir/$name" ;;
        *)          printf '#!/bin/sh\necho "9.9.9 (standard build, %s)"\n' "$name" > "$dir/$name" ;;
      esac
      chmod 0755 "$dir/$name"
    done
  done
  printf 'MZ windows binary\n' > "$dir/lyxbosa-windows-amd64.exe"
  printf 'MZ windows binary\n' > "$dir/lyxbosa-windows-arm64.exe"
  cp "$INSTALL_SH" "$dir/install.sh"
  cp "$INSTALL_PS1" "$dir/install.ps1"
  sums_over "$dir"
}

sums_over() {
  local dir="$1" tmp
  tmp="$(mktemp)"
  ( cd "$dir" && LC_ALL=C sha256sum -- $(find . -maxdepth 1 -type f \
      ! -name SHA256SUMS ! -name SHA256SUMS.minisig -printf '%f\n' | LC_ALL=C sort) ) > "$tmp"
  mv -f "$tmp" "$dir/SHA256SUMS"
}

# A throwaway keypair, so a real signature is verified rather than a real verification
# being skipped. The script takes the key list from LYXBOSA_INSTALL_KEYS for exactly this.
sign_release() {
  local dir="$1" keydir="$2"
  minisign -G -W -p "$keydir/k.pub" -s "$keydir/k.key" >/dev/null 2>&1 || return 1
  minisign -S -s "$keydir/k.key" -m "$dir/SHA256SUMS" -x "$dir/SHA256SUMS.minisig" \
    -t "LyxBoSa v9.9.9 SHA256SUMS (LytraX/LyxBoSa)" -c "verify" >/dev/null 2>&1 || return 1
  sed -n 2p "$keydir/k.pub"
}

# One install run against a fabricated release. Prints everything the script printed and
# returns its exit status.
run_install() {
  local origin="$1" key="$2"; shift 2
  env LYXBOSA_INSTALL_ORIGIN="file://$origin" LYXBOSA_INSTALL_KEYS="$key" \
      HOME="$TESTDIR/home" PATH="/usr/bin:/bin" \
      sh "$INSTALL_SH" "$@" 2>&1
}

# ---------------------------------------------------------------------------------------
selftest() {
  TESTDIR="$(mktemp -d "${TMPDIR:-/tmp}/install-scripts-selftest.XXXXXX")" || exit 1
  # shellcheck disable=SC2064
  trap "rm -rf '$TESTDIR'" EXIT
  mkdir -p "$TESTDIR/home"

  # The functions under test, in this shell. `main` is not run: the guard exists for this.
  # shellcheck disable=SC1090
  LYXBOSA_INSTALL_NO_MAIN=1 . "$INSTALL_SH"
  # install.sh sets `set -eu` and declares globals of its own, and both arrive here. The
  # errexit would end the run at the first case that is meant to fail; `WORK` is the name
  # this file used to use for its scratch directory, and sourcing emptied it, which pointed
  # every path below at the filesystem root. Hence TESTDIR, and hence the case beneath.
  set +e
  check "sourcing install.sh leaves this suite's scratch directory alone" \
        "$(test -d "$TESTDIR" && echo present)" "present"

  # ------------------------------------------------------------------------- agreement
  echo "=== the lists the scripts cannot read at run time ==="

  local want got
  want="$(cpp_owned_prefixes | LC_ALL=C sort | tr '\n' ' ')"
  got="$(printf '%s\n' "$OWNED_PREFIXES" | LC_ALL=C sort | tr '\n' ' ')"
  check "install.sh refuses exactly the prefixes InstallPath.cpp refuses" "$got" "$want"
  check "  ...and there are twelve of them" \
        "$(cpp_owned_prefixes | wc -l)" "12"
  # The direction that makes the list worth having: /usr/local/bin must NOT be on it, or
  # root would have nowhere to install that can still update itself.
  if cpp_owned_prefixes | grep -qx '/usr/local/bin'; then
    fail "  ...and /usr/local/bin is deliberately not among them"
  else
    pass "  ...and /usr/local/bin is deliberately not among them"
  fi

  check "install.sh's glibc floor is BuildIdentity.cpp's" \
        "$GLIBC_MIN_MINOR" "$(cpp_glibc_floor)"
  check "install.sh's amd64 loader path is BuildIdentity.cpp's" \
        "$(loader_path amd64)" "$(cpp_loader_paths | sed -n 1p)"
  check "install.sh's arm64 loader path is BuildIdentity.cpp's" \
        "$(loader_path arm64)" "$(cpp_loader_paths | sed -n 2p)"
  check "install.sh's amd64 libc search list is BuildIdentity.cpp's, in order" \
        "$(libc_paths amd64 | tr '\n' ' ')" "$(cpp_libc_paths | sed -n 1,4p | tr '\n' ' ')"
  check "install.sh's arm64 libc search list is BuildIdentity.cpp's, in order" \
        "$(libc_paths arm64 | tr '\n' ' ')" "$(cpp_libc_paths | sed -n 5,8p | tr '\n' ' ')"

  want="$(keyring_keys | LC_ALL=C sort | tr '\n' ' ')"
  check "install.sh carries the keys in keys/minisign-trusted.txt" \
        "$(printf '%s\n' "$BUILTIN_KEYS" | LC_ALL=C sort | tr '\n' ' ')" "$want"
  got="$(ps1_keys | LC_ALL=C sort | tr '\n' ' ')"
  check "install.ps1 carries them too (its TEXT; no PowerShell here)" "$got" "$want"

  # Neither script may fetch itself or anything it verifies from a mutable branch path. A
  # file served from a branch is covered by no checksum list and signed by no key.
  # Comment lines dropped first: both scripts EXPLAIN in their headers why a branch path is
  # the wrong place to serve from, so "the string appears" is not the question. The same
  # distinction control-suites.py draws between a flag a tool dispatches on and one it names.
  if { sed 's/^[[:space:]]*#.*//' "$INSTALL_SH"; sed 's/^[[:space:]]*#.*//' "$INSTALL_PS1"; } \
       | grep -q 'raw\.githubusercontent\.com'; then
    fail "neither script fetches anything from a mutable branch path"
  else
    pass "neither script fetches anything from a mutable branch path"
  fi
  ok   "install.sh fetches from releases/latest/download/" \
       grep -q 'releases/latest/download' "$INSTALL_SH"
  ok   "install.ps1 fetches from releases/latest/download/ (its TEXT)" \
       grep -q 'releases/latest/download' "$INSTALL_PS1"

  # ------------------------------------------------- the release has to publish them
  echo
  echo "=== the release job ==="
  # The whole design rests on these being ASSETS. Served from a branch they would be
  # covered by no checksum list and signed by no key, and the scripts' own self-check,
  # their pinned keys and every sentence in docs/INSTALL.md would be describing something
  # that is not true.
  ok "the release job stages install.sh into artifacts/" \
     grep -q 'cp scripts/install.sh scripts/install.ps1 artifacts/' "$WORKFLOW"
  local staged checksummed
  staged="$(workflow_step_line 'Stage the install scripts beside the binaries')"
  checksummed="$(workflow_step_line 'Checksum every asset')"
  if [ -n "$staged" ] && [ -n "$checksummed" ] && [ "$staged" -lt "$checksummed" ]; then
    pass "  ...before the checksum step, which is the only ordering that covers them"
  else
    fail "  ...before the checksum step, which is the only ordering that covers them"
    printf '      stage at line %s, checksum at line %s\n' "${staged:-none}" "${checksummed:-none}"
  fi
  check "--expect counts every asset the release publishes" \
        "$(workflow_expect)" "$(fixture_names | wc -l)"
  ok "  ...and both scripts are among them" \
     bash -c 'f="$(sed -n "/^FIXTURE_NAMES=(/,/)\$/p" "'"$RELEASE_CHECKSUMS"'")"
              case "$f" in *install.sh*) ;; *) exit 1 ;; esac
              case "$f" in *install.ps1*) ;; *) exit 1 ;; esac'
  ok "the Windows job runs install.ps1's own controls" \
     grep -q 'install.ps1 -SelfTest' "$WORKFLOW"

  # ------------------------------------------------------------------------- refusals
  echo
  echo "=== destinations ==="

  local prefix
  while IFS= read -r prefix; do
    [ -n "$prefix" ] || continue
    check "$prefix/lyxbosa is refused as a destination" \
          "$(owner_of "$prefix/lyxbosa")" "$prefix"
  done < <(cpp_owned_prefixes)

  check "/usr/local/bin is accepted"          "$(owner_of /usr/local/bin)" ""
  check "$HOME/.local/bin is accepted"        "$(owner_of "$TESTDIR/home/.local/bin")" ""
  # Component-wise, not a string prefix. /usr/binary-thing is a directory nobody owns and
  # refusing it would be refusing a perfectly good destination for the wrong reason.
  check "/usr/binary-thing is not inside /usr/bin" "$(owner_of /usr/binary-thing)" ""
  check "/usr/bin itself is refused"          "$(owner_of /usr/bin)" "/usr/bin"
  # A spelling that walks back into an owned prefix. Without the resolution in
  # normalise_dir this passes the check on its typed form and installs into /bin.
  got="$(owner_of "$(normalise_dir /usr/local/bin/../../bin)")"
  if [ -n "$got" ]; then
    pass "a ..-spelled path back into an owned prefix is still refused (as $got)"
  else
    fail "a ..-spelled path back into an owned prefix is still refused"
  fi
  check "a relative path is resolved before it is judged" \
        "$(normalise_dir .)" "$(pwd -P)"

  echo
  echo "=== architectures ==="
  # detect_arch reads uname, so the mapping is asserted through a stubbed uname.
  local stub="$TESTDIR/stub"; mkdir -p "$stub"
  stub_uname() { printf '#!/bin/sh\necho "%s"\n' "$1" > "$stub/uname"; chmod 0755 "$stub/uname"; }
  stub_uname x86_64; check "x86_64 maps to amd64" "$(PATH="$stub:$PATH" detect_arch)" "amd64"
  stub_uname aarch64; check "aarch64 maps to arm64" "$(PATH="$stub:$PATH" detect_arch)" "arm64"
  stub_uname armv7l
  if ( PATH="$stub:$PATH" detect_arch ) >/dev/null 2>&1; then
    fail "an architecture with no asset is refused, not guessed at"
  else
    pass "an architecture with no asset is refused, not guessed at"
  fi

  echo
  echo "=== would the standard build run here: all three answers ==="
  # None of these is observable on this machine, which can only ever demonstrate one.
  local loader="$TESTDIR/loader"; : > "$loader"
  make_libc "$TESTDIR/libc-2.27" GLIBC_2.2.5 GLIBC_2.27 GLIBC_PRIVATE
  make_libc "$TESTDIR/libc-2.28" GLIBC_2.2.5 GLIBC_2.28 GLIBC_PRIVATE
  make_libc "$TESTDIR/libc-2.43" GLIBC_2.2.5 GLIBC_2.34 GLIBC_2.43 GLIBC_PRIVATE
  make_libc "$TESTDIR/libc-none" GLIBC_2.2.5 GLIBC_PRIVATE GLIBC_2.3.4
  printf 'not an elf at all\nGLIBC_2.99\n' > "$TESTDIR/libc-notelf"

  check "no loader at all is 'no', whatever else is true" \
        "$(standard_build_here_at "$TESTDIR/nonexistent-loader" "$TESTDIR/libc-2.43")" "no"
  check "glibc 2.27 is 'no' - one release below the floor" \
        "$(standard_build_here_at "$loader" "$TESTDIR/libc-2.27")" "no"
  check "glibc 2.28 is 'yes' - the floor itself" \
        "$(standard_build_here_at "$loader" "$TESTDIR/libc-2.28")" "yes"
  check "glibc 2.43 is 'yes'" \
        "$(standard_build_here_at "$loader" "$TESTDIR/libc-2.43")" "yes"
  check "a loader and no readable glibc is 'unknown', not a guess" \
        "$(standard_build_here_at "$loader" "$TESTDIR/nothing-here")" "unknown"
  check "a libc declaring only GLIBC_2.2.5 and GLIBC_PRIVATE is 'unknown'" \
        "$(standard_build_here_at "$loader" "$TESTDIR/libc-none")" "unknown"
  # The whole-file read is what makes this necessary: without the ELF magic check a file
  # that merely contains the right letters would be believed.
  check "a file that is not an ELF is not read as one" \
        "$(standard_build_here_at "$loader" "$TESTDIR/libc-notelf")" "unknown"
  # The first READABLE one decides, the same rule the C++ uses, so a host with several is
  # answered identically by both.
  check "the first readable libc decides, not the highest" \
        "$(standard_build_here_at "$loader" "$TESTDIR/absent" "$TESTDIR/libc-2.27" "$TESTDIR/libc-2.43")" "no"
  # And the number itself, against the host's own glibc, cross-checked below.
  check "GLIBC_2.2.5 and GLIBC_PRIVATE are skipped rather than half-parsed" \
        "$(highest_glibc_minor "$TESTDIR/libc-2.43")" "43"

  echo
  echo "=== which build gets installed ==="
  check "a flag wins over everything"                 "$(choose_build standard portable no)"  "standard"
  check "  ...in the other direction too"             "$(choose_build portable standard yes)" "portable"
  check "an existing portable install is NOT moved"   "$(choose_build '' portable yes)"       "portable"
  check "an existing standard install stays standard" "$(choose_build '' standard yes)"       "standard"
  check "a fresh install on a capable host: standard" "$(choose_build '' '' yes)"             "standard"
  check "a fresh install on an old host: portable"    "$(choose_build '' '' no)"              "portable"
  check "a host that cannot be read: portable"        "$(choose_build '' '' unknown)"         "portable"
  check "an unreadable existing install: portable"    "$(choose_build '' unknown unknown)"    "portable"

  # ------------------------------------------------------------------------- end to end
  echo
  echo "=== a fabricated release, installed for real ==="
  local origin="$TESTDIR/origin" dest="$TESTDIR/dest" key out
  make_release "$origin"
  mkdir -p "$dest"

  if ! command -v minisign >/dev/null 2>&1; then
    say "minisign is not installed - the signature cases cannot run here" "NOT EXERCISED"
  else
    key="$(sign_release "$origin" "$TESTDIR")" || key=""
    if [ -z "$key" ]; then
      fail "a throwaway key could be generated and used to sign the fixture"
    else
      pass "a throwaway key could be generated and used to sign the fixture"

      out="$(run_install "$origin" "$key" --dir "$dest" --standard)"
      if [ -x "$dest/lyxbosa" ] && "$dest/lyxbosa" --version 2>/dev/null | grep -q '^9\.9\.9'; then
        pass "a good install lands and the binary runs"
      else
        fail "a good install lands and the binary runs"
        printf '%s\n' "$out" | sed 's/^/      /'
      fi
      ok   "  ...and it says the signature was checked" \
           grep -q 'verified: minisign signature over SHA256SUMS' <<<"$out"
      ok   "  ...and it names the release from the signed trusted comment" \
           grep -q 'release:  v9.9.9' <<<"$out"
      ok   "  ...and it says which build it installed" \
           grep -q 'build:    standard (lyxbosa-linux-amd64)' <<<"$out"

      # --portable is how somebody crosses on purpose, and it is the only way to.
      rm -f "$dest/lyxbosa"
      out="$(run_install "$origin" "$key" --dir "$dest" --portable)"
      ok   "--portable installs the portable asset" \
           grep -q 'build:    portable (lyxbosa-linux-amd64-portable)' <<<"$out"

      # The other direction, which is what makes the verification a verification: one byte
      # changed in the signed list.
      rm -f "$dest/lyxbosa"
      printf 'X' >> "$origin/SHA256SUMS"
      out="$(run_install "$origin" "$key" --dir "$dest")"
      nope "a SHA256SUMS with one byte changed is refused" test -e "$dest/lyxbosa"
      ok   "  ...and it says the signature did not verify" \
           grep -q 'does not verify under any key' <<<"$out"
      sums_over "$origin"
      minisign -S -s "$TESTDIR/k.key" -m "$origin/SHA256SUMS" -x "$origin/SHA256SUMS.minisig" \
        -t "LyxBoSa v9.9.9 SHA256SUMS (LytraX/LyxBoSa)" -c "verify" >/dev/null 2>&1
    fi
  fi

  # Without minisign the script must install and say plainly that it got the weaker check.
  # Simulated rather than depended on: a control that can only observe absence on a machine
  # that happens to lack the tool is not a control.
  rm -f "$dest/lyxbosa"
  out="$(MINISIGN="$TESTDIR/no-such-minisign" run_install "$origin" "" --dir "$dest" --standard)"
  ok   "with no minisign it still installs" test -x "$dest/lyxbosa"
  ok   "  ...and says SHA-256 only, naming what that does not cover" \
       grep -q 'verified: SHA-256 against SHA256SUMS only' <<<"$out"
  if grep -q 'minisign signature over' <<<"$out"; then
    fail "  ...and never claims the signature it did not check"
  else
    pass "  ...and never claims the signature it did not check"
  fi

  # A download whose hash is not the one in the list.
  rm -f "$dest/lyxbosa"
  printf '#!/bin/sh\necho tampered\n' > "$origin/lyxbosa-linux-amd64"
  out="$(MINISIGN="$TESTDIR/no-such-minisign" run_install "$origin" "" --dir "$dest" --standard)"
  nope "a download that does not match SHA256SUMS is refused" test -e "$dest/lyxbosa"
  ok   "  ...and it says so rather than installing anyway" \
       grep -q 'does not match its SHA-256' <<<"$out"

  # An asset the signed list says nothing about.
  sums_over "$origin"
  rm -f "$origin/SHA256SUMS.minisig"
  grep -v ' lyxbosa-linux-amd64$' "$origin/SHA256SUMS" > "$TESTDIR/s" && mv "$TESTDIR/s" "$origin/SHA256SUMS"
  rm -f "$dest/lyxbosa"
  out="$(MINISIGN="$TESTDIR/no-such-minisign" run_install "$origin" "" --dir "$dest" --standard)"
  nope "an asset with no line in SHA256SUMS is refused" test -e "$dest/lyxbosa"
  ok   "  ...and refuses rather than installing it unchecked" \
       grep -q 'has no line for lyxbosa-linux-amd64' <<<"$out"

  # And the destination refusal end to end, which must happen BEFORE anything is fetched.
  out="$(MINISIGN="$TESTDIR/no-such-minisign" run_install "$origin" "" --dir /usr/bin)"
  ok   "an install into /usr/bin is refused end to end" \
       grep -q 'which a package manager owns' <<<"$out"
  ok   "  ...and it explains that such a binary could never update itself" \
       grep -q 'can never update itself' <<<"$out"

  # ------------------------------------------------------------------------- the ps1
  echo
  echo "=== install.ps1, by inspection only ==="
  local var
  for var in 'ProgramFiles' 'ProgramFiles(x86)' 'ProgramW6432' 'SystemRoot'; do
    ok "it refuses everything under %$var%" \
       grep -qF "\${env:$var}" "$INSTALL_PS1"
  done
  ok "it installs under LOCALAPPDATA\\Programs\\lyxbosa" \
     grep -qF 'Programs\lyxbosa' "$INSTALL_PS1"
  ok "it adds the install directory to the user PATH" \
     grep -q "SetEnvironmentVariable('Path'" "$INSTALL_PS1"
  ok "it carries a -SelfTest the Windows job can run" \
     grep -q 'if ($SelfTest) { exit (Invoke-SelfTest) }' "$INSTALL_PS1"
  ok "it verifies a signature when minisign is present" \
     grep -q "Get-Command minisign" "$INSTALL_PS1"
  ok "it hashes every download" grep -q 'Get-FileHash' "$INSTALL_PS1"

  echo
  if [ $_ok -eq 0 ]; then
    echo "cases: $_cases - every one correct"
  else
    echo "cases: $_cases - AT LEAST ONE CONTROL FAILED"
  fi
  return $_ok
}

case "${1:-}" in
  --selftest) selftest ;;
  *) echo "usage: install-scripts.sh --selftest" >&2; exit 2 ;;
esac
