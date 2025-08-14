FROM golang:1.25.0 AS build
WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -trimpath -ldflags=-buildid= -o main .
RUN mkdir -p /mounts/config;

FROM ghcr.io/greboid/dockerbase/nonroot:1.20250803.0
COPY --from=build /src/main /thp
COPY --from=build --chown=65532:65532 /mounts /
ENTRYPOINT ["/thp", "--tailscale-config-dir=/config"]
