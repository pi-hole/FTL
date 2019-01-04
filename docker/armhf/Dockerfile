FROM debian:stretch

RUN dpkg --add-architecture armhf && \
    apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev:armhf gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh libcap-dev:armhf

ENV CC arm-linux-gnueabihf-gcc
