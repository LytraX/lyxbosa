FROM almalinux:8

# Install build dependencies + GCC 12 for C++20 support
# AlmaLinux 8 AppStream has cmake 3.20 (>=3.18 needed for vcpkg output passthrough)
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
