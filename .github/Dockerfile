FROM ghcr.io/pi-hole/ftl-build:v2.23

WORKDIR /app

COPY . /app

ARG CI_ARCH="linux/amd64"
ENV CI_ARCH=${CI_ARCH}
ARG GIT_BRANCH="test"
ENV GIT_BRANCH=${GIT_BRANCH}
ARG GIT_TAG="test"
ENV GIT_TAG=${GIT_TAG}
ARG BUILD_OPTS=""
ENV BUILD_OPTS=${BUILD_OPTS}

# Setting TERM is needed for pretty output in BATS tests
ENV TERM=xterm

# CI starts from a fresh checkout every time, so cmake has no build tree to
# compare against and recompiles all 207 translation units on every run - on
# riscv64, sqlite3.c alone is over half of that under QEMU. ccache is keyed on
# content rather than on mtimes in a build tree, so it survives the fresh clone
# and only units that actually changed are compiled. Installed here rather than
# in ftl-build while we measure the payoff; move it into the image once proven.
RUN apk add --no-cache ccache
ENV CCACHE_DIR=/app/.ccache
ENV CCACHE_MAXSIZE=500M

# Build FTL
# Remove possible old build files
RUN rm -rf cmake && \
# Start from clean counters so the statistics below describe this build alone
    ccache --zero-stats && \
# Build and test FTL
    bash build.sh "-DSTATIC=${STATIC} -DBUILD_TAR_REGRESSION=ON -DBUILD_GZIP_REGRESSION=ON -DBUILD_DOTDOH_REGRESSION=ON -DCMAKE_C_COMPILER_LAUNCHER=ccache" ${BUILD_OPTS} && \
# Report what the cache saved, so the CI log shows whether it is worth keeping
    ccache --show-stats && \
# Copy FTL binary to root directory
    cd / &&\
    cp /app/pihole-FTL . && \
# Create tarball of API docs
    tar -C /app/src/api/docs/content/ -czvf /api-docs.tar.gz . && \
# Generate default config file
    ./pihole-FTL create-default-config pihole.toml
