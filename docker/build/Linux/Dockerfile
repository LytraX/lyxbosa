# The glibc build image.
#
# Three things decide what this image's compiler is, and each one of them moved on its own
# before it was written down here: the base layer, where the packages come from, and which
# vcpkg builds them. They are pinned below in that order.
#
# THE BASE LAYER, BY DIGEST
# -------------------------
# `almalinux:8` is a tag and a tag is a pointer. Pinned by digest the starting layer is the
# same bytes every time, which also pins the glibc, binutils and rpm database the build
# inherits. The tag is kept beside the digest for a reader; docker resolves the digest and
# ignores it. A digest that no longer resolves FAILS the build - there is no fallback to a
# tag, and that is the point of writing it this way rather than adding a check that could
# be skipped.
#
# It is an ARG so that the FROM line and the manifest recorded further down read one value
# rather than two that agree today, and so docker/build/check-pins.sh can plant a digest
# that does not resolve and watch the build refuse it. Nothing in a release overrides it.
#
# AlmaLinux 8 is also where the published glibc floor comes from - GLIBC_2.28 and
# GLIBCXX_3.4.22, which README.md states under "System support". Moving this line to a
# newer distribution moves that floor and strands every host the portable build exists for.
# build-inside.sh runs abi-floor on the binary it produced, so the two cannot drift apart
# quietly.
ARG BASE_IMAGE=almalinux:8.10-20260902@sha256:9f355ae942d6a6c0561f0771dc053a2cfae9580fc45fa4252756db7c7e80c09f
FROM ${BASE_IMAGE}
ARG BASE_IMAGE

# The three helpers this image needs, copied before the first line that uses one.
#
#   retry            everything that crosses a network this repository does not own
#   almalinux-repos  the mirror network swapped for the origin, and asserted
#   abi-floor        run by build-inside.sh on the binary it produced, so the floor
#                    README.md publishes is checked where it is decided
#
# Each is a file rather than a line inside a RUN because each has a --selftest that drives
# it in both directions, and a check nobody has watched fail is not yet a check.
COPY retry.sh /usr/local/bin/retry
COPY almalinux-repos.sh /usr/local/bin/almalinux-repos
COPY abi-floor.sh /usr/local/bin/abi-floor

# EPEL is not installed and is not missing: measured on this base digest, `epel-release` is
# the only package the whole build gains from enabling it - the toolchain, ninja-build and
# perl-IPC-Cmd all resolve from BaseOS, AppStream and PowerTools. It was a second mirror
# network, reached by metalink, for one package that nothing uses.
#
# perl and perl-IPC-Cmd are OpenSSL's, not ours. vcpkg builds OpenSSL from source for
# curl's `ssl` feature on Linux, its Configure is a Perl script, and the port fails
# outright - "Perl cannot find IPC::Cmd" - if the module is missing. AlmaLinux 8 ships
# a minimal perl that does not include it, so both are named. Windows builds OpenSSL
# too - for the update verifier, not for curl, which uses Schannel there - and vcpkg
# fetches a Perl of its own on that platform, so nothing has to be installed for it.
#
# AlmaLinux 8 AppStream has cmake 3.20 (>=3.18 needed for vcpkg output passthrough).
#
# THE COMPILER, BY ITS EXACT RELEASE
# ----------------------------------
# Asked for rather than asserted. It is the package whose identity reaches the published
# bytes - vcpkg's ABI hash covers it and every object in the binary carries its version
# string - and AppStream keeps superseded builds of it, so naming one keeps resolving to
# the same compiler after upstream ships the next. If it is ever withdrawn, dnf says no
# package matched and the build stops, which is the loud failure and not the quiet one.
# The result is checked anyway: `dnf install` of a name it resolved differently would
# otherwise be a silent substitution.
ARG GCC_TOOLSET=gcc-toolset-12-gcc-c++-12.2.1-7.8.el8_10
RUN chmod +x /usr/local/bin/retry /usr/local/bin/almalinux-repos /usr/local/bin/abi-floor \
    && almalinux-repos \
    && retry dnf -y --refresh install dnf-plugins-core \
    && dnf config-manager --set-enabled powertools \
    && retry dnf -y install \
        "${GCC_TOOLSET}" \
        gcc-c++ \
        cmake \
        ninja-build \
        git \
        curl \
        zip \
        unzip \
        tar \
        make \
        pkgconfig \
        perl \
        perl-IPC-Cmd \
    && installed="$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' gcc-toolset-12-gcc-c++)" \
    && if [ "${installed}" != "${GCC_TOOLSET}" ]; then \
           echo "asked for ${GCC_TOOLSET} and got ${installed}" >&2; exit 1; \
       fi \
    && dnf clean all

# WHICH VCPKG
# -----------
# vcpkg-configuration.json pins the registry baseline, which pins the PORT VERSIONS. It
# says nothing about the tool that builds them: vcpkg's own cmake, its toolchain files and
# its ABI hashing all come from this clone, and cloning the default branch means whatever
# was on it that morning. The commit is in docker/build/vcpkg-commit so that the two Linux
# images and docker/build/Windows/build.ps1 read one value rather than three that agree
# today, and so that the workflow can put it in the binary-cache key - a tool change that
# the key could not see would restore dependency artefacts built by another one.
#
# Cloned in full and then checked out, rather than fetched shallow: vcpkg fetches the
# baseline commit into this same object store when it resolves the default registry, and a
# repository with no history is a shape that has not been measured here.
#
# The checkout is asserted for the same reason the repository rewrite is. `git checkout` of
# a commit that is not there fails, but a clone that silently produced something else would
# not, and the assertion costs one command.
ENV VCPKG_ROOT=/opt/vcpkg
COPY vcpkg-commit /tmp/vcpkg-commit
RUN VCPKG_COMMIT="$(tr -d '[:space:]' < /tmp/vcpkg-commit)" \
    && retry git clone https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} \
    && git -C ${VCPKG_ROOT} checkout --detach "${VCPKG_COMMIT}" \
    && at="$(git -C ${VCPKG_ROOT} rev-parse HEAD)" \
    && if [ "${at}" != "${VCPKG_COMMIT}" ]; then \
           echo "vcpkg is at ${at}, not the pinned ${VCPKG_COMMIT}" >&2; exit 1; \
       fi \
    && ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics \
    && rm -f /tmp/vcpkg-commit

# WHAT IS STILL NOT PINNED, WRITTEN DOWN WHERE A BUILD CAN READ IT
# ----------------------------------------------------------------
# Every RPM except the compiler is whatever dnf resolved on the day this image was built.
# AlmaLinux 8.10's repository serves current versions, so freezing the set is not a thing
# this file can do - a superseded build of most packages is simply gone. What it can do is
# record what it got, so that two builds that disagree have somewhere to be diffed and a
# rebuilder is not left guessing. build-inside.sh prints the head of this and names the
# path; docs/RELEASING.md says what may be concluded from it.
RUN { echo "base-image: ${BASE_IMAGE}"; \
      echo "vcpkg-commit: $(git -C ${VCPKG_ROOT} rev-parse HEAD)"; \
      echo "compiler: $(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' gcc-toolset-12-gcc-c++)"; \
      echo "packages:"; \
      rpm -qa --qf '  %{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort; \
    } > /etc/lyxbosa-builder-manifest

# vcpkg writes here when VCPKG_DEFAULT_BINARY_CACHE points at it; created up front
# so the mount does not land on a missing directory.
RUN mkdir -p /vcpkg-cache

WORKDIR /src

# Build script
COPY Linux/build-inside.sh /build-inside.sh
RUN chmod +x /build-inside.sh

ENTRYPOINT ["/build-inside.sh"]
