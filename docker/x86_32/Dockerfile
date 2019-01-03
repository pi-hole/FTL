FROM debian:stretch

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev:i386 gcc gcc-multilib \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh libcap-dev

ENV CC gcc
