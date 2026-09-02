#pragma once

#include "config/Config.h"
#include <fmt/base.h>

namespace lyxbosa {

// Orchestrates the init-config command workflow
class InitConfigUseCase {
public:
    int execute() {
        fmt::print("{}", Config::generateDefault());
        return 0;
    }
};

}  // namespace lyxbosa
