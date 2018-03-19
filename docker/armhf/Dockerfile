FROM debian:stretch

RUN dpkg --add-architecture armhf && \
    apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev:armhf gcc-arm-linux-gnueabihf \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh

ENV CC arm-linux-gnueabihf-gcc
