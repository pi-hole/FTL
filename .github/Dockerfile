FROM ghcr.io/pi-hole/ftl-build:v2.11 AS builder

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

# Monkeypatch BATS to remove duplicate output of starting and finished test
# BATS uses ANSI escape codes to overwrite the line after the test has finished
# This is not supported by Github Actions as it does not provide a TTY to the docker build container
RUN sed -i '/buffer_with_truncation /d' /bats-core/libexec/bats-core/bats-format-pretty

# Build FTL
# Remove possible old build files
RUN rm -rf cmake && \
# Build and test FTL
    bash build.sh "-DSTATIC=${STATIC}" test ${BUILD_OPTS} && \
# Move FTL binary to root directory
    cd / &&\
    mv /app/pihole-FTL . && \
# Create tarball of API docs
    tar -C /app/src/api/docs/content/ -czvf /api-docs.tar.gz .

# Create final image containing only the FTL binary and API docs
FROM scratch AS result
COPY --from=builder /pihole-FTL /pihole-FTL
COPY --from=builder /api-docs.tar.gz /api-docs.tar.gz
