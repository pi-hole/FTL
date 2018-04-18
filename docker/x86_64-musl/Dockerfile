FROM debian:stretch

RUN apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev musl-tools \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh

ENV CC musl-gcc
