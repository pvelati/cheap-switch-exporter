# syntax=docker/dockerfile:1

# BUILDPLATFORM keeps the toolchain native while cross-compiling, so building
# for a Raspberry Pi from an amd64 host does not run Go under emulation.
#
# Pin a patched Go release, not just the minor line: the go directive in go.mod
# is only a minimum, and the standard library in an early 1.25 patch carries
# advisories that would otherwise end up in the shipped binary. Verified with
# govulncheck under this exact toolchain.
FROM --platform=$BUILDPLATFORM golang:1.25.14-alpine3.24 AS build

WORKDIR /app

# Dependencies first so the layer is reused whenever only sources change.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# TARGETOS/TARGETARCH are provided by buildx; the defaults keep a plain
# "docker build" working. VERSION is injected instead of being derived from git,
# which lets .dockerignore keep the .git directory out of the build context.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build \
    -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o /out/cheap-switch-exporter \
    .

FROM alpine:3.24

LABEL maintainer="Paolo Velati <paolo.velati@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/pvelati/cheap-switch-exporter"
LABEL org.opencontainers.image.description="Prometheus Exporter for cheap switch boxes without SNMP"
LABEL org.opencontainers.image.licenses="MIT"

RUN adduser -D -u 1000 appuser

COPY --from=build /out/cheap-switch-exporter /bin/cheap-switch-exporter
COPY config.yaml.example /etc/cheap-switch-exporter/config.yaml.example

USER appuser

VOLUME ["/etc/cheap-switch-exporter"]
EXPOSE 8080

# Liveness only: /healthz does not poll the switch, so the health check cannot
# turn into a second scraper hammering the device.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD wget -q -O- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/bin/cheap-switch-exporter"]
CMD ["-c", "/etc/cheap-switch-exporter/config.yaml"]
