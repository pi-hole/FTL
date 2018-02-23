FROM debian:stretch

ARG Arch
ARG CC
ARG Packages

RUN dpkg --add-architecture $Arch && \
    apt-get update && \
    apt-get install -y nettle-dev:$Arch $Packages make file wget netcat-traditional sqlite3 git ca-certificates ssh

ENV CC $CC
