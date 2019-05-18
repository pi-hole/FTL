FROM debian:stretch

# Packages required to install compiler and libraries
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget git ca-certificates

# Use Raspbian's GCC
# This command was taken from https://github.com/dockcross/dockcross/blob/master/linux-armv6/Dockerfile
# Slightly modified from the original
RUN mkdir rpi_tools && cd rpi_tools && git init && git remote add origin https://github.com/raspberrypi/tools && \
    git config core.sparseCheckout true && \
    echo "arm-bcm2708/arm-rpi-4.9.3-linux-gnueabihf" >> .git/info/sparse-checkout && \
    git pull --depth=1 origin master && \
    cp -a arm-bcm2708/arm-rpi-4.9.3-linux-gnueabihf/* /usr/ && rm -rf ../rpi_tools

RUN wget ftl.pi-hole.net/libraries/libgmp.a -O /usr/local/lib/libgmp.a && \
    wget ftl.pi-hole.net/libraries/libnettle.a -O /usr/local/lib/libnettle.a && \
    wget ftl.pi-hole.net/libraries/libhogweed.a -O /usr/local/lib/libhogweed.a && \
    wget ftl.pi-hole.net/libraries/libcap.so.2.25 -O /usr/local/lib/libcap.so

RUN dpkg --add-architecture armhf && \
    apt-get update && \
    apt-get install -y --no-install-recommends make file netcat-traditional ssh \
        nettle-dev:armhf libcap-dev sqlite3

# Install ghr for GitHub Releases: https://github.com/tcnksm/ghr
RUN wget https://github.com/tcnksm/ghr/releases/download/v0.12.0/ghr_v0.12.0_linux_amd64.tar.gz && \
    tar -xzf ghr_*_linux_amd64.tar.gz && \
    mv ghr_*_linux_amd64/ghr /usr/bin/ghr

# Allow libnettle to be used, because this GCC doesn't have all the right header and library directories
ENV CC "arm-linux-gnueabihf-gcc -I/usr/include -I/usr/include/arm-linux-gnueabihf -L/usr/local/lib"
