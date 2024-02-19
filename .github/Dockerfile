FROM ghcr.io/pi-hole/ftl-build:v2.5 AS builder

WORKDIR /app

COPY . /app

ARG CI_ARCH="linux/amd64"
ENV CI_ARCH ${CI_ARCH}
ARG GIT_BRANCH="test"
ENV GIT_BRANCH ${GIT_BRANCH}
ARG GIT_TAG="test"
ENV GIT_TAG ${GIT_TAG}

# Build FTL
# Remove possible old build files
RUN rm -rf cmake && \
# Build FTL
    bash build.sh "-DSTATIC=${STATIC}" && \
# Run binary architecture tests
    bash test/arch_test.sh && \
# Run full test suite
    bash test/run.sh && \
# Move FTL binary to root directory
    cd / &&\
    mv /app/pihole-FTL . && \
# Create tarball of API docs
    tar -C /app/src/api/docs/content/ -czvf /api-docs.tar.gz .

# Create final image containing only the FTL binary and API docs
FROM scratch AS result
COPY --from=builder /pihole-FTL /pihole-FTL
COPY --from=builder /api-docs.tar.gz /api-docs.tar.gz
