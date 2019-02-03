FROM debian:stretch

RUN apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev gcc libc-dev \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh libcap-dev

ENV CC gcc
