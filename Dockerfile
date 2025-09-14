FROM --platform=${BUILDPLATFORM:-linux/amd64} docker.io/golang:1.25.0 AS build

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -ldflags="-s -w" -ldflags '-extldflags "-static"' -trimpath -ldflags=-buildid= -o main .
RUN mkdir -p /mounts/config;

FROM --platform=${BUILDPLATFORM:-linux/amd64} ghcr.io/greboid/dockerbase/nonroot:1.20250803.0
COPY --from=build /src/main /thp
COPY --from=build --chown=65532:65532 /mounts /
ENTRYPOINT ["/thp", "--tailscale-config-dir=/config"]
