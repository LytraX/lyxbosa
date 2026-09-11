#pragma once

// BuildIdentity.h - which of the published builds this binary is, and whether the other
// one would have run here.
//
// Two questions, and they are not the same question.
//
//   WHICH BUILD AM I. Answered from macros the compiler and CMake already set, so it is
//   free, certain, and printed unconditionally by --version. It is the first thing any
//   support conversation needs and the last thing anybody wants to work out by hand from
//   a file listing.
//
//   WOULD THE STANDARD BUILD RUN HERE. Only the portable build ever asks, and only to
//   decide whether saying "there is a faster build for this host" is useful or is noise
//   about a choice the reader does not have. A static musl binary has no glibc to ask,
//   so this is read off the host's own files - see standardBuildHere() for exactly what
//   that can and cannot establish.

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace lyxbosa {

// True for the statically linked build published as lyxbosa-linux-<arch>-portable.
// False for the glibc build and on every other platform.
bool isPortableBuild();

// The parenthesised half of --version: which build this is, and the asset name a
// release publishes it as. Empty on a platform a release publishes nothing for, so
// --version there is the bare version rather than an invented description.
//
// The version itself stays the first whitespace-delimited token of --version, because
// `lyxbosa --version | awk '{print $1}'` is a thing people have already written.
std::string buildIdentity();

// Whether the standard build would load on this host.
//
// WHAT EACH ANSWER MEANS, because the difference is the whole design:
//
//   Yes      - proven. The dynamic loader is at the path the ABI fixes for this
//              architecture, a glibc was found, and it declares a symbol version at or
//              above what the standard build needs.
//   No       - proven. Either there is no dynamic loader at all, so no dynamically
//              linked glibc binary can start here whatever else is true, or a glibc was
//              found and it is older than the floor.
//   Unknown  - not proven, in either direction. The loader is there but no glibc could
//              be found, read or parsed.
//
// Only Yes is acted on. No and Unknown are both silence, which is what makes a host
// this cannot read indistinguishable from a host that has no alternative - the safe
// direction, and the reason this refuses rather than guessing.
//
// WHAT IT CANNOT TELL, stated because a check whose blind spots are not written down
// gets trusted for things it never measured:
//
//   It does not look at libstdc++. The standard build also needs GLIBCXX_3.4.22, and a
//   host with glibc 2.28 and no C++ runtime at all would be answered Yes here. Every
//   distribution that ships glibc 2.28 ships a newer libstdc++, so this is a gap rather
//   than a case, and it is the permissive direction: the reader is told a faster build
//   exists, not given one. If they take it and it will not start, it says so.
//
//   It does not look at the CPU. Both builds are built for the base architecture, so
//   there is nothing here that a host could be missing.
//
//   It reads a glibc, not necessarily THE glibc. A host with several, or with one
//   somewhere this does not look - a Nix or Guix store, a container's second root - is
//   answered No or Unknown and stays silent.
//
//   It is a fact about the host at the moment it is asked, and only a run that is
//   about to print asks. A host whose glibc is upgraded is therefore re-asked on the
//   next run past the notice's interval rather than never - see the interval in
//   UpdatePolicy.h - so an upgrade that creates the alternative is eventually noticed.
enum class StandardBuildHere { Yes, No, Unknown };

StandardBuildHere standardBuildHere();

// The same answer computed from an explicit loader path and libc search list, so that a
// test can present a host this machine is not: one with no loader, one whose glibc is
// too old, one whose libc is not readable as an ELF at all. standardBuildHere() is this
// with the paths the ABI and the distributions fix.
//
// It exists because the three answers above are not observable on a developer's machine,
// which can only ever demonstrate one of them - and an answer nobody has watched the
// check give is not an answer the check is known to be able to give.
StandardBuildHere standardBuildHereAt(const std::filesystem::path& loader,
                                      const std::vector<std::filesystem::path>& libcs);

// For --verbose and for test failure messages: an answer that reads as a sentence.
constexpr std::string_view standardBuildHereReason(StandardBuildHere a) {
    switch (a) {
        case StandardBuildHere::Yes:     return "the standard build would run here";
        case StandardBuildHere::No:      return "the standard build would not start here";
        case StandardBuildHere::Unknown: return "cannot tell whether the standard build "
                                                "would start here";
    }
    return "unknown";
}

// The sentence a scan prints when a portable build is running on a host that could have
// had the faster one. Empty for every other case, including the one that matters most:
// a host with no alternative is told nothing, because there is nothing it could do.
std::string portableBuildNotice();

// The same sentence built for a named standard asset, with neither gate applied.
//
// It exists for the same reason standardBuildHereAt() does: the sentence the shipped
// binary produces is observable on almost no machine. It needs a musl build, and a musl
// build's natural home - Alpine - has no glibc, so portableBuildNotice() is empty there
// and every assertion about the wording SKIPS in the one container that runs the
// portable build's own tests. This one answers on any host and in any build, so the
// claims the wording has to keep - that it names the standard asset, that it does not
// name the one the reader already has, and that it quotes no percentage - are asserted
// wherever the suite runs rather than nowhere.
std::string portableBuildNoticeFor(std::string_view standardAsset);

}  // namespace lyxbosa
