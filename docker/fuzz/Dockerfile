# The fuzzing toolchain, which is not the toolchain anything else here uses.
#
# libFuzzer ships with clang's compiler-rt and has no GCC equivalent, and this machine
# has neither clang nor AFL. So the fuzzers are built where a clang exists, the same way
# the release binaries are built where an old glibc exists: in a container, from a pinned
# base, with the build tree INSIDE it. docker/build/Linux/build-inside.sh configures at
# /build and copies out what it made, and this does the same - which is why fuzzing adds
# no fourth build directory to the repository. See AGENTS.md, "Build directories".
FROM ubuntu:24.04

# clang-18 for libFuzzer and the sanitizers; libclang-rt-18-dev is where libclang_rt.fuzzer
# and the ASan/UBSan runtimes actually live and it is NOT pulled in by clang alone on
# Ubuntu. llvm-18 is for llvm-profdata/llvm-cov, which turn a campaign into a coverage
# figure - a fuzzer that reports crashes and not coverage has told you nothing about the
# harness.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang-18 \
      lld-18 \
      llvm-18 \
      libclang-rt-18-dev \
      cmake \
      ninja-build \
      git \
      curl \
      ca-certificates \
      zip \
      unzip \
      tar \
      make \
      pkg-config \
      python3 \
      perl \
      bsdextrautils \
    && rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/bin/clang-18 /usr/local/bin/clang \
    && ln -s /usr/bin/clang++-18 /usr/local/bin/clang++ \
    && ln -s /usr/bin/llvm-profdata-18 /usr/local/bin/llvm-profdata \
    && ln -s /usr/bin/llvm-cov-18 /usr/local/bin/llvm-cov \
    && ln -s /usr/bin/llvm-symbolizer-18 /usr/local/bin/llvm-symbolizer

ENV CC=/usr/local/bin/clang
ENV CXX=/usr/local/bin/clang++

# A full clone, not a shallow one: vcpkg-configuration.json pins a baseline commit and a
# --depth 1 clone does not contain it.
ENV VCPKG_ROOT=/opt/vcpkg
RUN git clone https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} \
    && ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

# The dependencies, installed in their own layer from the manifest alone, so that editing
# a source file does not rebuild OpenSSL. /deps holds a copy of the manifest rather than a
# mount, because a mount is not part of the image and would not cache.
COPY vcpkg.json vcpkg-configuration.json /deps/
COPY triplets /deps/triplets
RUN ${VCPKG_ROOT}/vcpkg install \
      --x-manifest-root=/deps \
      --overlay-triplets=/deps/triplets \
      --triplet=x64-linux-fuzz \
      --x-install-root=/deps/vcpkg_installed \
    && rm -rf ${VCPKG_ROOT}/buildtrees ${VCPKG_ROOT}/packages ${VCPKG_ROOT}/downloads

WORKDIR /src
COPY docker/fuzz/build-inside.sh /build-inside.sh
RUN chmod +x /build-inside.sh
ENTRYPOINT ["/build-inside.sh"]
