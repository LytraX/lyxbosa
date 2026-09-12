// content_fuzzer.cpp - libFuzzer entry point for the rule engine.
//
// The body is in FuzzTargets.h so that tests/fuzz_replay_test.cpp runs the same code in
// the ordinary build. Nothing but the entry point belongs here.

#include "FuzzTargets.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void)lyxbosa::fuzz::runContentTarget(data, size);
    return 0;
}
