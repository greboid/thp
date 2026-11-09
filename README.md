# THP - Tailscale Proxy

A simple HTTP reverse proxy that runs on Tailscale, allowing you to securely expose internal services, it uses Tailscale's 
build in LetsEncrypt support to add certificates and adds tailscale auth headers.

This project was heavily inspired by [tsp](https://github.com/csmith/tsp) and I did initially copy the code and I used the same flags, to make switching easier.

## Command Line Flags

| Flag                     | Environment Variable   | Default    | Description                                                                                   |
|--------------------------|------------------------|------------|-----------------------------------------------------------------------------------------------|
| `--tailscale-hostname`   | `TAILSCALE_HOSTNAME`   | `tsp`      | Hostname for the Tailscale device                                                             |
| `--tailscale-port`       | `TAILSCALE_PORT`       | `443`      | Port to listen on for incoming connections                                                    |
| `--tailscale-config-dir` | `TAILSCALE_CONFIG_DIR` | `config`   | Path to store Tailscale configuration                                                         |
| `--tailscale-auth-key`   | `TAILSCALE_AUTH_KEY`   | (empty)    | Tailscale auth key for connecting to the network. If blank, interactive auth will be required |
| `--upstream`             | `UPSTREAM`             | (required) | URL of the upstream service to proxy HTTP requests to (e.g., `http://localhost:8080`)         |
| `--upstream-timeout`     | `UPSTREAM_TIMEOUT`     | `60s`      | How long to wait for the upstream to start responding before failing the request (`0` = wait forever) |
| `--use-upstream-host`    | `USE_UPSTREAM_HOST`    | `false`    | Send the upstream's host as the `Host` header instead of the host the client requested. The client's host is still sent in `X-Forwarded-Host` |
| `--ssl`                  | `SSL`                  | `true`     | Whether to enable Tailscale SSL                                                               |
| `--authheaders`          | `AUTHHEADERS`          | `true`     | Whether to add Tailscale auth headers                                                         |
| `--redirect`             | `REDIRECT`             | `false`    | Whether to redirect plain HTTP requests to the proxy (HTTPS unless `ssl` is false)            |
| `--redirect-port`        | `REDIRECT_PORT`        | `80`       | The port to listen on for plain HTTP requests if `redirect` is true                           |

## Authentication Headers

When `--authheaders` is enabled, TSP will add the following headers to proxied requests:

- `Tailscale-User-Login`: User's login name
- `Tailscale-User-Name`: User's display name  
- `Tailscale-User-Profile-Pic`: URL to user's profile picture

Any `Tailscale-User-*` headers sent by the client are always removed, including variants
using underscores or different case (e.g. `Tailscale_User_Login`), whether or not
`--authheaders` is enabled, so they cannot be forged.

The headers are only added when the request comes from a device owned by a user. Requests
from tagged devices, from the public internet via Funnel, or whose identity cannot be
resolved are proxied without them, so upstreams should treat a missing header as
"not authenticated".

## Example Usage

```bash
# Basic usage
./thp --upstream=http://localhost:8080

# With auth key and hostname specified
./thp --upstream=http://localhost:3000 --tailscale-hostname=myapp --tailscale-auth-key=tskey-auth-xxxxx
```

## Docker Compose Example

```yaml
services:
  thp:
    image: ghcr.io/greboid/thp:latest
    environment:
      - UPSTREAM=http://app:80
      - TAILSCALE_HOSTNAME=myapp
      - TAILSCALE_AUTH_KEY=tskey-auth-xxxxx
    volumes:
      - ./config:/config
    restart: unless-stopped
    depends_on:
      - app
  app:
    image: nginx:alpine
    container_name: app
    restart: unless-stopped
```
