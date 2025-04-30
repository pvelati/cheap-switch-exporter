FROM golang:1.24.2-alpine3.21 AS build

LABEL maintainer="Martin Kjellstrand <madworx@github>"
LABEL org.opencontainers.image.source="https://github.com/madworx/cheap-switch-exporter"
LABEL org.opencontainers.image.description="Prometheus Exporter for cheap switch boxes without SNMP"

RUN apk add --no-cache git make

WORKDIR /app

COPY . .

RUN go mod download && go mod verify

RUN make cheap-switch-exporter

FROM scratch

COPY --from=build /app/cheap-switch-exporter /app/config.yaml.example /

ENTRYPOINT ["/cheap-switch-exporter"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["/cheap-switch-exporter", "-healthcheck"]
