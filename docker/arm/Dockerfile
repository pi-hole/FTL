FROM debian:stretch

RUN dpkg --add-architecture armel && \
    apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev:armel gcc-arm-linux-gnueabi libc6-dev-armel-cross \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh libcap-dev:armel

ENV CC arm-linux-gnueabi-gcc
