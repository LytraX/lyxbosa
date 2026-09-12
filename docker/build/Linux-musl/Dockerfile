# The musl build image. Alpine is musl natively, so nothing here is a cross toolchain:
# the system gcc, cmake and ninja produce a binary whose only libc is the one linked
# into it.
#
# Why this image exists at all, beside docker/build/Linux/Dockerfile: the glibc build
# from almalinux:8 needs GLIBC_2.27 and GLIBCXX_3.4.22 at run time and does not start on
# a host older than that, and a glibc build linked with -static starts there and then
# segfaults in getaddrinfo, because glibc's resolver dlopens the host's NSS modules
# even from a static binary. musl resolves names itself, with no NSS and no dlopen, so
# a static musl binary has one libc and it is the one it was built with.
#
# THE BASE LAYER, BY DIGEST
# -------------------------
# alpine:3.24 is a tag and a tag moves within its branch - this digest is 3.24.1. The
# compiler is part of vcpkg's ABI hash, so a base image that moved would invalidate every
# cached dependency and rebuild them all without any file in this repository having
# changed. Pinned by digest that cannot happen silently: bumping it here is a change the
# cache key sees, because the workflow hashes this file. The tag is kept beside the digest
# for a reader; docker resolves the digest and ignores it, and a digest that no longer
# resolves fails the build rather than falling back.
# It is an ARG so the FROM line and the manifest recorded further down read one value
# rather than two that agree today, and so docker/build/check-pins.sh can plant a digest
# that does not resolve and watch the build refuse it. Nothing in a release overrides it.
ARG BASE_IMAGE=alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
FROM ${BASE_IMAGE}
ARG BASE_IMAGE

# retry is used for everything that crosses a network this repository does not own. Alpine
# fetches from one CDN rather than from a mirror list, so the failure this covers here is
# an outage and not the metadata race that took the glibc image down on 2026-09-12 - see
# that Dockerfile. It is the same script for both because two copies are two copies.
COPY retry.sh /usr/local/bin/retry

# perl is OpenSSL's, exactly as the AlmaLinux image says: vcpkg builds OpenSSL from
# source for curl's `ssl` feature, its Configure is Perl, and it needs IPC::Cmd. Alpine's
# `perl` package carries that module in the core, so there is no second package to name.
#
# ninja-build provides /usr/bin/ninja-build; ninja-is-really-ninja is the symlink that
# makes it answer to `ninja`, which is the name vcpkg and cmake -G Ninja both call.
#
# linux-headers: musl-dev does not ship the kernel headers, and abseil (through re2)
# and libzip include a few of them.
#
# THE COMPILER IS ASSERTED, NOT REQUESTED
# ---------------------------------------
# Alpine's branch repository serves the current build of each package and nothing else, so
# `gcc=15.2.0-r5` would stop resolving the day the branch ships r6 - a pin that breaks
# every build rather than holding one. What is written down instead is what this image is
# expected to contain, checked after the install: a compiler that moved fails the image
# build with the version it found, and the repair is to bump these two lines deliberately.
# That is the loud half of the same trade the glibc image makes by naming an exact RPM,
# and it lands in the binary-cache key either way because the workflow hashes this file.
#
# `apk info -e -v` and not `apk info -v`: the second prints the package DESCRIPTION and no
# version at all, so the comparison read an empty string and this assertion fired on its
# first real build. It fired in the right direction - refusing rather than passing blind -
# which is the only reason the mistake cost a minute instead of a release.
ARG EXPECT_GCC=15.2.0-r5
ARG EXPECT_MUSL=1.2.6-r2
RUN chmod +x /usr/local/bin/retry \
    && retry apk add --no-cache \
        bash \
        build-base \
        cmake \
        ninja-build \
        ninja-is-really-ninja \
        git \
        curl \
        zip \
        unzip \
        tar \
        pkgconf \
        perl \
        linux-headers \
        file \
    && got_gcc="$(apk info -e -v gcc | sed -n 's/^gcc-//p')" \
    && got_musl="$(apk info -e -v musl | sed -n 's/^musl-//p')" \
    && if [ -z "${got_gcc}" ] || [ -z "${got_musl}" ]; then \
           echo "read no version for gcc or musl: got '${got_gcc}' and '${got_musl}'" >&2; \
           echo "a version this could not read is not a version that matched." >&2; \
           exit 1; \
       fi \
    && if [ "${got_gcc}" != "${EXPECT_GCC}" ] || [ "${got_musl}" != "${EXPECT_MUSL}" ]; then \
           echo "this image expects gcc ${EXPECT_GCC} and musl ${EXPECT_MUSL};" >&2; \
           echo "the branch now serves gcc ${got_gcc} and musl ${got_musl}." >&2; \
           echo "bump EXPECT_GCC/EXPECT_MUSL in this file once the change is understood." >&2; \
           exit 1; \
       fi

# vcpkg's bootstrap and its tool acquisition both download prebuilt binaries for Linux,
# and those are glibc binaries. VCPKG_FORCE_SYSTEM_BINARIES tells it to use the cmake,
# ninja, git and so on installed above instead. The vcpkg tool itself has a musl
# build upstream, which bootstrap picks when it sees musl; where it has none, this
# variable makes bootstrap compile the tool from source.
#
# WHICH VCPKG
# -----------
# vcpkg-configuration.json pins the registry baseline, which pins the PORT VERSIONS. The
# tool that builds them - its cmake, its toolchain files, its ABI hashing - comes from this
# clone, and the default branch is whatever was on it that morning. One commit, in
# docker/build/vcpkg-commit, read by both Linux images and by the Windows script, and
# hashed into the binary-cache key so a tool change cannot restore artefacts built by
# another one.
ENV VCPKG_ROOT=/opt/vcpkg
ENV VCPKG_FORCE_SYSTEM_BINARIES=1
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

# What is still not pinned, written where a build can read it: every apk except the two
# asserted above is whatever the branch served on the day this image was built. Alpine
# keeps only current versions, so freezing the set is not something this file can do -
# recording it is, and a rebuilder comparing two images has somewhere to diff.
RUN { echo "base-image: ${BASE_IMAGE}"; \
      echo "vcpkg-commit: $(git -C ${VCPKG_ROOT} rev-parse HEAD)"; \
      echo "compiler: $(apk info -e -v gcc) $(apk info -e -v musl)"; \
      echo "packages:"; \
      apk info -v | sort | sed 's/^/  /'; \
    } > /etc/lyxbosa-builder-manifest

# vcpkg writes here when VCPKG_DEFAULT_BINARY_CACHE points at it; created up front
# so the mount does not land on a missing directory.
RUN mkdir -p /vcpkg-cache

WORKDIR /src

COPY Linux-musl/build-inside.sh /build-inside.sh
RUN chmod +x /build-inside.sh

ENTRYPOINT ["/build-inside.sh"]
