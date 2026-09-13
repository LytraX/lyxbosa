#pragma once

#include "config/Config.h"
#include "infrastructure/Delivery.h"
#include "infrastructure/Terminal.h"

namespace lyxbosa {

// Orchestrates the init-config command workflow
class InitConfigUseCase {
public:
    explicit InitConfigUseCase(const Terminal& terminal) : terminal_(terminal) {}

    // `lyxbosa init-config > lyxbosa.yaml` is the documented use, so the configuration on
    // standard output is the whole answer, and a truncated one on a full disk is not a success.
    int execute() {
        CheckedOutput out(stdout);
        out.print("{}", Config::generateDefault());
        return finishAnswerOnStandardOutput(terminal_, out, "the configuration", 0);
    }

private:
    const Terminal& terminal_;
};

}  // namespace lyxbosa
