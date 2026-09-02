#include "perl.h"
#include <array>

namespace lyxbosa::rules::perl {

// PL001: Perl eval with user input
namespace detail_PL001 {
    static constexpr Pattern patterns[] = {
        { R"((?i:eval)\s*\(\s*\$ENV\{)",
          "Perl eval with ENV", false,
          {"eval"} },
        { R"((?i:eval)\s+\$ARGV)",
          "Perl eval with ARGV", false,
          {"argv", "eval"} },
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
// XOR of two 100+ char strings is ALWAYS malicious - no legitimate use
namespace detail_PL002 {
    static constexpr Pattern patterns[] = {
        { R"(['"][A-Za-z0-9+/=\-]{100,}['"]\s*\^\s*['"][A-Za-z0-9+/=\-]{100,}['"])",
          "Long string XOR", false },
    };
}
const BuiltinRule PL002 {
    .code = {Category::Perl, 2},
    .name = "Perl XOR obfuscation",
    .description = "Detects XOR obfuscation in Perl scripts",
    .severity = Severity::Critical,
    .patterns = detail_PL002::patterns,
};

// PL003: Perl backdoor with socket
namespace detail_PL003 {
    static constexpr Pattern patterns[] = {
        { R"(socket\s*\(\s*\w+\s*,\s*PF_INET\s*,\s*SOCK_STREAM)",
          "Perl socket creation", false,
          {"sock_stream", "pf_inet", "socket"} },
        { R"(IO::Socket::INET->new)",
          "Perl IO::Socket", false,
          {"io::socket::inet->new"} },
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
        { R"(((?i:system)|(?i:exec))\s*\(\s*['"][^'"]*\$ENV)",
          "system/exec with ENV", false,
          {"system|exec"} },
        { R"(((?i:system)|(?i:exec))\s*\(\s*\$ARGV)",
          "system/exec with ARGV", false,
          {"system|exec", "argv"} },
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
        { R"(open\s*\(\s*\w+\s*,\s*['"]>\s*&)",
          "Perl file descriptor redirect", false,
          {"open"} },
        { R"(dup2\s*\()",
          "Perl dup2 call", false,
          {"dup2"} },
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
// Patterns must distinguish IRC commands from SQL JOINs
// IRC channels: #channel (single #), Joomla tables: #__table (# followed by __)
namespace detail_PL006 {
    static constexpr Pattern patterns[] = {
        { R"(PRIVMSG\s+#\w+\s*:)",
          "IRC PRIVMSG to channel", false,
          {"privmsg"} },
        { R"(["']JOIN\s+#[a-zA-Z])",
          "IRC JOIN channel command", false,
          {"join"} },
        { R"(NICK\s+[a-zA-Z]\w*\\r\\n)",
          "IRC NICK command", false,
          {"nick"} },
        { R"(print\s+\$sock\s+["'])",
          "IRC socket write", false,
          {"print", "sock"} },
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
        { R"(Net::SMTP->new)",
          "Net::SMTP usage", false,
          {"net::smtp->new"} },
        { R"(sendmail.*?-t\s+-oi)",
          "sendmail command", false,
          {"sendmail"} },
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
// NOTE: Pattern tightened due to false positives matching PHP code
// The old pattern (for ($i=0...socket...connect) matched across many lines
namespace detail_PL008 {
    static constexpr Pattern patterns[] = {
        // Perl-specific: fork bomb in loop with socket send
        { R"(fork\s*\(\s*\).*?socket\s*\([^)]+\).*?send\s*\()",
          "Perl fork bomb with socket", false,
          {"socket", "send", "fork"} },
    };
}
const BuiltinRule PL008 {
    .code = {Category::Perl, 8},
    .name = "Perl DDoS tool",
    .description = "Detects Perl-based flooding/DDoS tools",
    .severity = Severity::Critical,
    .patterns = detail_PL008::patterns,
};

// PL009: Perl regex code execution
// The (?{...}) construct inside regex executes Perl code - often abused
// Pattern: '...'=~('(?{' ... '})') - common webshell pattern
namespace detail_PL009 {
    static constexpr Pattern patterns[] = {
        { R"(=~\s*\(\s*['"]?\(\?\{)",
          "Perl regex code execution", false },
    };
}
const BuiltinRule PL009 {
    .code = {Category::Perl, 9},
    .name = "Perl regex code execution",
    .description = "Detects (?{...}) regex code execution pattern",
    .severity = Severity::Critical,
    .patterns = detail_PL009::patterns,
};

static const std::array<const BuiltinRule*, RULE_COUNT> ALL_RULES = {
    &PL001, &PL002, &PL003, &PL004,
    &PL005, &PL006, &PL007, &PL008, &PL009
};

const BuiltinRule* const* getAllRules() {
    return ALL_RULES.data();
}

} // namespace lyxbosa::rules::perl
