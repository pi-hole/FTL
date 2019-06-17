FROM debian:stretch

RUN apt-get update && \
    apt-get install -y --no-install-recommends nettle-dev gcc libc-dev \
        make file wget netcat-traditional sqlite3 git ca-certificates ssh libcap-dev \
        dnsutils libcap2-bin && rm -rf /var/lib/apt/lists/*

# Install ghr for GitHub Releases: https://github.com/tcnksm/ghr
RUN wget https://github.com/tcnksm/ghr/releases/download/v0.12.0/ghr_v0.12.0_linux_amd64.tar.gz && \
    tar -xzf ghr_*_linux_amd64.tar.gz && rm ghr_*_linux_amd64.tar.gz && \
    mv ghr_*_linux_amd64/ghr /usr/bin/ghr

ENV CC gcc

#RUN git clone https://github.com/pi-hole/FTL && cd FTL
#RUN cd FTL && make -j 4
#RUN cd FTL && test/run.sh
