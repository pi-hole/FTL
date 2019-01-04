FROM debian:stretch

RUN dpkg --add-architecture armhf && \
    apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev:armhf \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh libcap-dev:armhf

# Use Raspbian's GCC
# This command was taken from https://github.com/dockcross/dockcross/blob/master/linux-armv6/Dockerfile
# Slightly modified from the original
RUN mkdir rpi_tools && cd rpi_tools && git init && git remote add origin https://github.com/raspberrypi/tools && \
    git config core.sparseCheckout true && \
    echo "arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64" >> .git/info/sparse-checkout && \
    git pull --depth=1 origin master && \
    cp -a arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/* /usr/ && rm -rf ../rpi_tools

RUN wget ftl.pi-hole.net/libraries/libgmp.a -O /usr/local/lib/libgmp.a && \
    wget ftl.pi-hole.net/libraries/libnettle.a -O /usr/local/lib/libnettle.a && \
    wget ftl.pi-hole.net/libraries/libhogweed.a -O /usr/local/lib/libhogweed.a

# Allow libnettle to be used, because this GCC doesn't have all the right header and library directories
ENV CC "arm-linux-gnueabihf-gcc -I/usr/include -I/usr/include/arm-linux-gnueabihf -L/usr/lib/arm-linux-gnueabihf"
