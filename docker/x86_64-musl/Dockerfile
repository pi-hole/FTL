FROM alpine:edge

# 1st line: Packages needed for building
# 2nd line: Packaged needed by the CI
# 3rd line: Packages needed for testing
RUN apk add --no-cache alpine-sdk linux-headers gmp-dev nettle-dev \
                       openssh-client \
                       sqlite bash bind-tools libcap shadow

# Install ghr for GitHub Releases: https://github.com/tcnksm/ghr
RUN wget https://github.com/tcnksm/ghr/releases/download/v0.12.0/ghr_v0.12.0_linux_amd64.tar.gz && \
    tar -xzf ghr_*_linux_amd64.tar.gz && rm ghr_*_linux_amd64.tar.gz && \
    mv ghr_*_linux_amd64/ghr /usr/bin/ghr

ENV CC gcc

#RUN git clone https://github.com/pi-hole/FTL && cd FTL
#RUN cd FTL && make -j 4
#RUN cd FTL && test/run.sh
