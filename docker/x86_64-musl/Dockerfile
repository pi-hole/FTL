FROM alpine:edge

# Install ghr for GitHub Releases: https://github.com/tcnksm/ghr
RUN wget https://github.com/tcnksm/ghr/releases/download/v0.12.0/ghr_v0.12.0_linux_amd64.tar.gz && \
    tar -xzf ghr_*_linux_amd64.tar.gz && rm ghr_*_linux_amd64.tar.gz && \
    mv ghr_*_linux_amd64/ghr /usr/bin/ghr

# First line: Packages needed for building
# Second line: Packages needed for testing
RUN apk add --no-cache alpine-sdk linux-headers gmp-dev nettle-dev \
                       sqlite bash bind-tools libcap shadow

RUN git clone https://github.com/pi-hole/FTL && cd FTL && git checkout tweak/musl_support

RUN cd FTL && make -j 4
