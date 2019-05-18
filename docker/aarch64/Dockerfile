FROM debian:stretch

RUN dpkg --add-architecture arm64 && \
    apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev:arm64 gcc-aarch64-linux-gnu libc-dev-arm64-cross \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh libcap-dev:arm64

# Install ghr for GitHub Releases: https://github.com/tcnksm/ghr
RUN wget https://github.com/tcnksm/ghr/releases/download/v0.12.0/ghr_v0.12.0_linux_amd64.tar.gz && \
    tar -xzf ghr_*_linux_amd64.tar.gz && \
    mv ghr_*_linux_amd64/ghr /usr/bin/ghr

ENV CC aarch64-linux-gnu-gcc
