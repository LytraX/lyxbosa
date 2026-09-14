#pragma once

#include "infrastructure/Delivery.h"
#include "infrastructure/Terminal.h"
#include "system/CliArgs.h"

namespace lyxbosa {

// `lyxbosa --help`, `lyxbosa --version` and every command's --help.
//
// The text is the whole answer, and `lyxbosa --version | awk '{print $1}'` is a documented
// use of one of them, so each ends the way every other answer on standard output ends: written
// through a CheckedOutput and asked whether it arrived - see Delivery.h. A help text or a
// version that did not arrive exits 1 with the sentence, a reader that went away exits 141 and
// says nothing, and one that arrived exits 0 as it always has.
//
// The parser does not print either. CliArgs::parse() says how the library was stopped from
// printing and exiting on its own, which is what this command could not see past before.
class HelpUseCase {
public:
    explicit HelpUseCase(const Terminal& terminal) : terminal_(terminal) {}

    int execute(const CliArgs& args) {
        CheckedOutput out(stdout);
        out.print("{}", args.answerText);
        return finishAnswerOnStandardOutput(
            terminal_, out, args.command == Command::Version ? "the version" : "the help text",
            0);
    }

private:
    const Terminal& terminal_;
};

}  // namespace lyxbosa
