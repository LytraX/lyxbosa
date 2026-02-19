ARG UBUNTU_VERSION=20.04
FROM ubuntu:${UBUNTU_VERSION}

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies + GCC 11 for C++20 support on older Ubuntu
# cmake from Kitware repo (>=3.18 needed for vcpkg output passthrough)
RUN apt-get update && apt-get install -y \
    software-properties-common \
    ca-certificates \
    gpg \
    wget \
    && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
    && wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null \
       | gpg --dearmor - > /usr/share/keyrings/kitware-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main" \
       > /etc/apt/sources.list.d/kitware.list \
    && apt-get update && apt-get install -y \
    build-essential \
    g++-11 \
    cmake \
    ninja-build \
    git \
    curl \
    zip \
    unzip \
    tar \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set GCC 11 as default
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-11

# Install vcpkg
ENV VCPKG_ROOT=/opt/vcpkg
RUN git clone https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} \
    && ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /src

# Build script
COPY build-inside.sh /build-inside.sh
RUN chmod +x /build-inside.sh

ENTRYPOINT ["/build-inside.sh"]
