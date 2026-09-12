// archive_fuzzer.cpp - libFuzzer entry point for the container path.
//
// The body is in FuzzTargets.h so that tests/fuzz_replay_test.cpp runs the same code in
// the ordinary build. Nothing but the entry point belongs here.

#include "FuzzTargets.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void)lyxbosa::fuzz::runArchiveTarget(data, size);
    return 0;
}
