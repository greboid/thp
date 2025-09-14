ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

FROM --platform=${BUILDPLATFORM:-linux/amd64} docker.io/golang:1.25.0 AS build

ENV TARGETPLATFORM=${TARGETPLATFORM}
ENV BUILDPLATFORM=${BUILDPLATFORM}
ENV TARGETOS=${TARGETOS}
ENV TARGETARCH=${TARGETARCH}

ENV CGO_ENABLED=0
ENV GOARCH=${TARGETARCH}
ENV GOOS=${TARGETOS}

WORKDIR /src
COPY . .

RUN go build -a -ldflags="-s -w" -ldflags '-extldflags "-static"' -trimpath -ldflags=-buildid= -o main .
RUN mkdir -p /mounts/config;

FROM ghcr.io/greboid/dockerbase/nonroot:1.20250803.0
COPY --from=build /src/main /thp
COPY --from=build --chown=65532:65532 /mounts /
ENTRYPOINT ["/thp", "--tailscale-config-dir=/config"]
