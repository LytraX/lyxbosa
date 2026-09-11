FROM almalinux:8

# Install build dependencies + GCC 12 for C++20 support
# AlmaLinux 8 AppStream has cmake 3.20 (>=3.18 needed for vcpkg output passthrough)
#
# perl and perl-IPC-Cmd are OpenSSL's, not ours. vcpkg builds OpenSSL from source for
# curl's `ssl` feature on Linux, its Configure is a Perl script, and the port fails
# outright - "Perl cannot find IPC::Cmd" - if the module is missing. AlmaLinux 8 ships
# a minimal perl that does not include it, so both are named. Windows builds OpenSSL
# too - for the update verifier, not for curl, which uses Schannel there - and vcpkg
# fetches a Perl of its own on that platform, so nothing has to be installed for it.
RUN dnf install -y epel-release dnf-plugins-core \
    && dnf config-manager --set-enabled powertools \
    && dnf install -y \
    gcc-c++ \
    gcc-toolset-12-gcc-c++ \
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
    && dnf clean all

# Install vcpkg (system GCC 8 is fine for bootstrapping)
ENV VCPKG_ROOT=/opt/vcpkg
RUN git clone https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} \
    && ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

# vcpkg writes here when VCPKG_DEFAULT_BINARY_CACHE points at it; created up front
# so the mount does not land on a missing directory.
RUN mkdir -p /vcpkg-cache

WORKDIR /src

# Build script
COPY build-inside.sh /build-inside.sh
RUN chmod +x /build-inside.sh

ENTRYPOINT ["/build-inside.sh"]
