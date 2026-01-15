#include "perl.h"
#include <array>

namespace lyxbosa::rules::perl {

// PL001: Perl eval with user input
namespace detail_PL001 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(eval\s*\(\s*\$ENV\{)">(),
          "Perl eval with ENV", false },
        { makePattern<R"(eval\s+\$ARGV)">(),
          "Perl eval with ARGV", false },
    };
}
const BuiltinRule PL001 {
    .code = {Category::Perl, 1},
    .name = "Perl eval with user input",
    .description = "Detects Perl eval() with environment/argument input",
    .severity = Severity::Critical,
    .patterns = detail_PL001::patterns,
};

// PL002: Perl XOR obfuscation
namespace detail_PL002 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(['"][A-Za-z0-9+/=\-]{100,}['"]\s*\^\s*['"][A-Za-z0-9+/=\-]{100,}['"])">(),
          "Long string XOR", false },
    };
}
const BuiltinRule PL002 {
    .code = {Category::Perl, 2},
    .name = "Perl XOR obfuscation",
    .description = "Detects XOR obfuscation in Perl scripts",
    .severity = Severity::High,
    .patterns = detail_PL002::patterns,
};

// PL003: Perl backdoor with socket
namespace detail_PL003 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(socket\s*\(\s*\w+\s*,\s*PF_INET\s*,\s*SOCK_STREAM)">(),
          "Perl socket creation", false },
        { makePattern<R"(IO::Socket::INET->new)">(),
          "Perl IO::Socket", false },
    };
}
const BuiltinRule PL003 {
    .code = {Category::Perl, 3},
    .name = "Perl socket backdoor",
    .description = "Detects Perl socket-based backdoors",
    .severity = Severity::High,
    .patterns = detail_PL003::patterns,
};

// PL004: Perl system/exec with user input
namespace detail_PL004 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"((system|exec)\s*\(\s*['"][^'"]*\$ENV)">(),
          "system/exec with ENV", false },
        { makePattern<R"((system|exec)\s*\(\s*\$ARGV)">(),
          "system/exec with ARGV", false },
    };
}
const BuiltinRule PL004 {
    .code = {Category::Perl, 4},
    .name = "Perl command injection",
    .description = "Detects system/exec with user-controlled input",
    .severity = Severity::Critical,
    .patterns = detail_PL004::patterns,
};

// PL005: Perl reverse shell
namespace detail_PL005 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(open\s*\(\s*\w+\s*,\s*['"]>\s*&)">(),
          "Perl file descriptor redirect", false },
        { makePattern<R"(dup2\s*\()">(),
          "Perl dup2 call", false },
    };
}
const BuiltinRule PL005 {
    .code = {Category::Perl, 5},
    .name = "Perl reverse shell",
    .description = "Detects Perl reverse shell patterns",
    .severity = Severity::Critical,
    .patterns = detail_PL005::patterns,
};

// PL006: Perl IRC bot
namespace detail_PL006 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(PRIVMSG.*?:\s*!)">(),
          "IRC PRIVMSG command", false },
        { makePattern<R"(JOIN\s+#)">(),
          "IRC JOIN channel", false },
    };
}
const BuiltinRule PL006 {
    .code = {Category::Perl, 6},
    .name = "Perl IRC bot",
    .description = "Detects IRC bot patterns in Perl",
    .severity = Severity::High,
    .patterns = detail_PL006::patterns,
};

// PL007: Perl mailer
namespace detail_PL007 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(Net::SMTP->new)">(),
          "Net::SMTP usage", false },
        { makePattern<R"(sendmail.*?-t\s+-oi)">(),
          "sendmail command", false },
    };
}
const BuiltinRule PL007 {
    .code = {Category::Perl, 7},
    .name = "Perl mass mailer",
    .description = "Detects Perl email sending capabilities",
    .severity = Severity::Medium,
    .patterns = detail_PL007::patterns,
};

// PL008: Perl DDoS tool
namespace detail_PL008 {
    static constexpr Pattern patterns[] = {
        { makePattern<R"(for\s*\(\s*\$i\s*=\s*0.*?socket.*?connect)">(),
          "Loop with socket connect", false },
    };
}
const BuiltinRule PL008 {
    .code = {Category::Perl, 8},
    .name = "Perl DDoS tool",
    .description = "Detects Perl-based flooding/DDoS tools",
    .severity = Severity::Critical,
    .patterns = detail_PL008::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &PL001, &PL002, &PL003, &PL004,
    &PL005, &PL006, &PL007, &PL008
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::perl
