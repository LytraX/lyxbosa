#!/bin/bash
set -euo pipefail

# The fuzzing session, inside the container.
#
#   /src    the repository, mounted read-only
#   /work   the campaign's working directory on the host: corpus, crashes, reports.
#           Gitignored there, because a fuzzer writes its corpus to disk and minimises
#           inputs into new files, and nothing that grows on its own belongs in a tree
#           somebody pushes.
#   /builds a docker volume holding /builds/fuzz and /builds/cov, so a rebuild is
#           incremental and no build directory is added to the repository.
#           docker/build/Linux/build-inside.sh configures at /build inside its own
#           container for the same reason; AGENTS.md, "Build directories", is why it
#           matters here.
#
# Subcommands: build | run <target> <seconds> [args...] | replay [target] |
#              coverage <target> | minimise <target> | shell

TARGETS=(archive content)

usage() {
    cat >&2 <<'EOF'
usage (inside the container; use docker/fuzz/fuzz.sh from outside):
  build                      configure and build both fuzz targets
  run <target> <seconds>     a bounded campaign; everything after is passed to libFuzzer
  replay [target]            run every seed and corpus file once, no mutation
  reproduce <target> <file>  run one input once, for triaging a crash
  minimise <target>          shrink the corpus to the smallest set with the same coverage
  coverage <target>          build instrumented, replay the corpus, print line coverage
  shell                      an interactive shell
targets: archive content
EOF
    exit 2
}

binary_for() {
    case "$1" in
        archive) echo /builds/fuzz/lyxbosa_fuzz_archive ;;
        content) echo /builds/fuzz/lyxbosa_fuzz_content ;;
        *) echo "unknown target '$1' (known: ${TARGETS[*]})" >&2; exit 2 ;;
    esac
}

configure_and_build() {
    local dir="$1"; shift
    cmake -B "${dir}" -S /src \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_CXX_SCAN_FOR_MODULES=OFF \
        -DBUILD_TESTS=OFF \
        -DLYXBOSA_TUI=OFF \
        -DLYXBOSA_FUZZERS=ON \
        -DVCPKG_INSTALLED_DIR=/deps/vcpkg_installed \
        -DVCPKG_MANIFEST_INSTALL=OFF \
        -DVCPKG_TARGET_TRIPLET=x64-linux-fuzz \
        -DVCPKG_OVERLAY_TRIPLETS=/src/triplets \
        -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake \
        "$@"
    cmake --build "${dir}" --target lyxbosa_fuzz_archive lyxbosa_fuzz_content
}

# CMAKE_CXX_SCAN_FOR_MODULES=OFF, because CMake 3.28 with Ninja and C++20 runs a module
# dependency scan over every source and the scanner is clang-scan-deps, which Ubuntu ships
# in clang-tools rather than in clang. Nothing in this project is a C++20 module, so the
# scan is pure cost even where the tool exists. Without this the configure fails inside
# FindThreads with "Could NOT find Threads", which names the wrong thing entirely: the
# try-compile did not fail to link, it failed to run a program that is not installed.

# Every run writes crashes where the host can see them, and symbolises them. A crash
# whose stack is a column of hex addresses is a crash nobody triages.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=0:symbolize=1:print_stacktrace=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}"
export ASAN_SYMBOLIZER_PATH=/usr/local/bin/llvm-symbolizer

CMD="${1:-}"; shift || true
case "${CMD}" in

build)
    configure_and_build /builds/fuzz
    ls -l /builds/fuzz/lyxbosa_fuzz_archive /builds/fuzz/lyxbosa_fuzz_content
    ;;

run)
    TARGET="${1:-}"; SECONDS_BUDGET="${2:-}"; shift 2 || usage
    [ -n "${TARGET}" ] && [ -n "${SECONDS_BUDGET}" ] || usage
    BIN="$(binary_for "${TARGET}")"
    [ -x "${BIN}" ] || configure_and_build /builds/fuzz

    CORPUS="/work/corpus/${TARGET}"
    ARTIFACTS="/work/artifacts/${TARGET}"
    SEEDS="/src/fuzz/seeds/${TARGET}"
    mkdir -p "${CORPUS}" "${ARTIFACTS}"

    # The seeds are copied in rather than passed as a second corpus directory. libFuzzer
    # writes new inputs into the FIRST directory it is given, and /src is mounted
    # read-only precisely so that a fuzzer cannot grow a directory inside the repository.
    if [ -d "${SEEDS}" ]; then
        cp -n "${SEEDS}"/* "${CORPUS}/" 2>/dev/null || true
    fi

    echo "=== ${TARGET}: ${SECONDS_BUDGET}s, corpus $(ls -1 "${CORPUS}" | wc -l) inputs ==="

    # Into the artifacts directory before starting, because -jobs writes fuzz-<n>.log
    # beside the working directory and the working directory is /src, which is mounted
    # read-only on purpose. A campaign that cannot write its own log is a campaign whose
    # findings are only on somebody's terminal.
    cd "${ARTIFACTS}"
    # -max_len bounds a single input. The archive guards permit 256 MB of expansion per
    # archive, so a small input can legitimately buy a great deal of work; an unbounded
    # input length spends the whole campaign in a handful of enormous units.
    #
    # -timeout=90 rather than something snappier, and this is a judgement worth stating.
    # ArchiveConfig::timeBudgetSeconds defaults to 60, so an archive is ALLOWED to work
    # for a minute before its own guard stops it. A shorter libFuzzer timeout would
    # report the guard doing its job as a hang. Past 90 s the guard has been given its
    # full budget and a grace margin and has not stopped the input: that is the defect
    # this flag is looking for.
    exec "${BIN}" \
        -max_total_time="${SECONDS_BUDGET}" \
        -timeout=90 \
        -rss_limit_mb=4096 \
        -malloc_limit_mb=2048 \
        -max_len=65536 \
        -print_final_stats=1 \
        -artifact_prefix="${ARTIFACTS}/" \
        "$@" \
        "${CORPUS}"
    ;;

replay)
    TARGET="${1:-}"
    if [ -z "${TARGET}" ]; then
        for t in "${TARGETS[@]}"; do "$0" replay "$t"; done
        exit 0
    fi
    BIN="$(binary_for "${TARGET}")"
    [ -x "${BIN}" ] || configure_and_build /builds/fuzz
    INPUTS=()
    [ -d "/src/fuzz/seeds/${TARGET}" ] && INPUTS+=("/src/fuzz/seeds/${TARGET}")
    [ -d "/src/fuzz/regressions/${TARGET}" ] && INPUTS+=("/src/fuzz/regressions/${TARGET}")
    [ -d "/work/corpus/${TARGET}" ] && INPUTS+=("/work/corpus/${TARGET}")
    [ ${#INPUTS[@]} -gt 0 ] || { echo "no inputs for ${TARGET}" >&2; exit 1; }
    mkdir -p "/work/artifacts/${TARGET}"
    echo "=== replay ${TARGET}: ${INPUTS[*]} ==="
    # -artifact_prefix even though nothing is being mutated. Handed directories rather
    # than files, libFuzzer does not name the input it was running when it died - it
    # prints a stack and stops - so without this a replay that finds something tells you
    # there is something and not what. The artifact is the bytes, which is what a
    # reproducer needs. The gcc replay in tests/fuzz_replay_test.cpp names the file
    # instead, because it iterates the files itself; between them you get both.
    "${BIN}" -runs=0 -timeout=90 -rss_limit_mb=4096 \
        -artifact_prefix="/work/artifacts/${TARGET}/" "${INPUTS[@]}"
    ;;

reproduce)
    # One input, once, with everything the campaign had. A crashing input is triaged by
    # being run on its own: a `run` with the input appended would replay the whole corpus
    # beside it and bury the stack in thirty minutes of other output.
    TARGET="${1:-}"; INPUT="${2:-}"; shift 2 || usage
    [ -n "${TARGET}" ] && [ -n "${INPUT}" ] || usage
    BIN="$(binary_for "${TARGET}")"
    [ -x "${BIN}" ] || configure_and_build /builds/fuzz
    # The host says fuzz/work/x, the container says /work/x. Accept either rather than
    # making somebody translate a path they just copied out of a listing.
    case "${INPUT}" in
        fuzz/work/*) INPUT="/work/${INPUT#fuzz/work/}" ;;
    esac
    [ -f "${INPUT}" ] || { echo "no such input: ${INPUT}" >&2; exit 1; }
    echo "=== reproduce ${TARGET}: ${INPUT} ($(stat -c %s "${INPUT}") bytes) ==="
    mkdir -p "/work/artifacts/${TARGET}"
    "${BIN}" -runs=1 -timeout=90 -rss_limit_mb=4096 -malloc_limit_mb=2048 \
        -artifact_prefix="/work/artifacts/${TARGET}/" "$@" "${INPUT}"
    ;;

minimise)
    TARGET="${1:-}"; [ -n "${TARGET}" ] || usage
    BIN="$(binary_for "${TARGET}")"
    [ -x "${BIN}" ] || configure_and_build /builds/fuzz
    mkdir -p "/work/corpus-min/${TARGET}"
    "${BIN}" -merge=1 -max_len=65536 "/work/corpus-min/${TARGET}" "/work/corpus/${TARGET}"
    echo "minimised: $(ls -1 "/work/corpus-min/${TARGET}" | wc -l) of $(ls -1 "/work/corpus/${TARGET}" | wc -l)"
    ;;

coverage)
    TARGET="${1:-}"; [ -n "${TARGET}" ] || usage
    configure_and_build /builds/cov -DLYXBOSA_FUZZER_COVERAGE=ON
    case "${TARGET}" in
        archive) BIN=/builds/cov/lyxbosa_fuzz_archive ;;
        content) BIN=/builds/cov/lyxbosa_fuzz_content ;;
        *) usage ;;
    esac
    OUT="/work/coverage/${TARGET}"
    mkdir -p "${OUT}"
    rm -f "${OUT}"/*.profraw "${OUT}"/*.profdata
    INPUTS=()
    [ -d "/src/fuzz/seeds/${TARGET}" ] && INPUTS+=("/src/fuzz/seeds/${TARGET}")
    [ -d "/work/corpus/${TARGET}" ] && INPUTS+=("/work/corpus/${TARGET}")
    LLVM_PROFILE_FILE="${OUT}/%p.profraw" "${BIN}" -runs=0 -timeout=90 -rss_limit_mb=4096 "${INPUTS[@]}"
    llvm-profdata merge -sparse "${OUT}"/*.profraw -o "${OUT}/merged.profdata"
    # Only this project's own sources. The line coverage of libzip or of RE2 is not what
    # the question "did the harness reach the code that matters" is asking.
    llvm-cov report "${BIN}" -instr-profile="${OUT}/merged.profdata" \
        /src/src-lib/cpp/archive /src/src-lib/cpp/core /src/src-lib/cpp/analysis \
        /src/src-lib/cpp/rules /src/src-lib/cpp/patterns \
        | tee "${OUT}/report.txt"
    llvm-cov report "${BIN}" -instr-profile="${OUT}/merged.profdata" \
        /src/src-lib/cpp/archive > "${OUT}/report-archive.txt"
    echo "coverage written to ${OUT}"
    ;;

shell)
    exec /bin/bash
    ;;

*)
    usage
    ;;
esac
