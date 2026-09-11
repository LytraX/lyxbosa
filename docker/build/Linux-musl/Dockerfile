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
# A minor tag rather than alpine:3. The compiler is part of vcpkg's ABI hash, so a base
# image that silently moved to the next Alpine would invalidate every cached dependency
# and rebuild them all without any file in this repository having changed. Bumping it
# here is a change the cache key sees, because the workflow hashes this file.
FROM alpine:3.24

# perl is OpenSSL's, exactly as the AlmaLinux image says: vcpkg builds OpenSSL from
# source for curl's `ssl` feature, its Configure is Perl, and it needs IPC::Cmd. Alpine's
# `perl` package carries that module in the core, so there is no second package to name.
#
# ninja-build provides /usr/bin/ninja-build; ninja-is-really-ninja is the symlink that
# makes it answer to `ninja`, which is the name vcpkg and cmake -G Ninja both call.
#
# linux-headers: musl-dev does not ship the kernel headers, and abseil (through re2)
# and libzip include a few of them.
RUN apk add --no-cache \
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
    file

# vcpkg's bootstrap and its tool acquisition both download prebuilt binaries for Linux,
# and those are glibc binaries. VCPKG_FORCE_SYSTEM_BINARIES tells it to use the cmake,
# ninja, git and so on installed above instead. The vcpkg tool itself has a musl
# build upstream, which bootstrap picks when it sees musl; where it has none, this
# variable makes bootstrap compile the tool from source.
ENV VCPKG_ROOT=/opt/vcpkg
ENV VCPKG_FORCE_SYSTEM_BINARIES=1
RUN git clone https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} \
    && ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

# vcpkg writes here when VCPKG_DEFAULT_BINARY_CACHE points at it; created up front
# so the mount does not land on a missing directory.
RUN mkdir -p /vcpkg-cache

WORKDIR /src

COPY build-inside.sh /build-inside.sh
RUN chmod +x /build-inside.sh

ENTRYPOINT ["/build-inside.sh"]
