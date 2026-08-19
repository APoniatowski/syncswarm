# syntax=docker/dockerfile:1
#
# SyncSwarm relay image. The relay is part of the SyncSwarm SDK Go module, so the
# build context is the SDK repository root. Build from there:
#
#   docker build -f relay/Dockerfile -t syncswarm-relay .
#
# (or `docker compose -f relay/docker-compose.yml up --build`).

FROM golang:1.24-alpine AS build
WORKDIR /src

# Cache module downloads separately from the source.
COPY go.mod go.sum ./
RUN go mod download

# Build a fully static binary so it runs on distroless/scratch.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/relay ./relay

# Prepare a data dir owned by the non-root runtime user (distroless has no shell,
# so it cannot mkdir/chown at runtime).
RUN mkdir -p /out/data

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/relay /usr/local/bin/relay
COPY --from=build --chown=65532:65532 /out/data /data

# Node identity + offline store-and-forward queue persist here.
VOLUME ["/data"]

ENV SYNCSWARM_STORAGE_DIR=/data \
    SYNCSWARM_HTTP_ADDR=:8080

# Discovery (UDP), data transfer (TCP), health/metrics (TCP).
EXPOSE 64512/udp
EXPOSE 64513/tcp
EXPOSE 8080/tcp

USER nonroot:nonroot

# Uses the binary's own probe so no shell/curl is needed in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/relay", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/relay"]
