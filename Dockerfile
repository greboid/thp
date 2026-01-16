ARG BUILDPLATFORM

FROM --platform=${BUILDPLATFORM:-linux/amd64} docker.io/golang:1.26rc2 AS build

ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0
ENV GOARCH=${TARGETARCH}
ENV GOOS=${TARGETOS}

WORKDIR /src
COPY . .

RUN echo ${GOOS} ${GOARCH}
RUN go build -a -ldflags="-s -w" -ldflags '-extldflags "-static"' -trimpath -ldflags=-buildid= -o main .
RUN mkdir -p /mounts/config;

FROM ghcr.io/greboid/dockerbase/nonroot:1.20251213.0
COPY --from=build /src/main /thp
COPY --from=build --chown=65532:65532 /mounts /
VOLUME /config
ENTRYPOINT ["/thp", "--tailscale-config-dir=/config"]
