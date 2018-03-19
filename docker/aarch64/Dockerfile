FROM debian:stretch

RUN dpkg --add-architecture arm64 && \
    apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev:arm64 gcc-aarch64-linux-gnu libc-dev-arm64-cross \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh

ENV CC aarch64-linux-gnu-gcc
