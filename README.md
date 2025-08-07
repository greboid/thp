# TSP - Tailscale Proxy

A simple HTTP reverse proxy that runs on Tailscale, allowing you to securely expose internal services, it uses Tailscale's 
build in LetsEncrypt support to add certificates and adds tailscale auth headers.

This project was heavily inspired by [tsp](https://github.com/csmith/tsp) by @csmith and I did initially copy the code and I used the same flags, to make switching easier.

## Command Line Flags

| Flag                     | Environment Variable   | Default    | Description                                                                                   |
|--------------------------|------------------------|------------|-----------------------------------------------------------------------------------------------|
| `--tailscale-hostname`   | `TAILSCALE_HOSTNAME`   | `tsp`      | Hostname for the Tailscale device                                                             |
| `--tailscale-port`       | `TAILSCALE_PORT`       | `443`      | Port to listen on for incoming connections                                                    |
| `--tailscale-config-dir` | `TAILSCALE_CONFIG_DIR` | `config`   | Path to store Tailscale configuration                                                         |
| `--tailscale-auth-key`   | `TAILSCALE_AUTH_KEY`   | (empty)    | Tailscale auth key for connecting to the network. If blank, interactive auth will be required |
| `--upstream`             | `UPSTREAM`             | (required) | URL of the upstream service to proxy HTTP requests to (e.g., `http://localhost:8080`)         |
| `--ssl`                  | `SSL`                  | `true`     | Whether to enable Tailscale SSL                                                               |
| `--authheaders`          | `AUTHHEADERS`          | `true`     | Whether to add Tailscale auth headers                                                         |

## Authentication Headers

When `--authheaders` is enabled, TSP will add the following headers to proxied requests:

- `Tailscale-User-Login`: User's login name
- `Tailscale-User-Name`: User's display name  
- `Tailscale-User-Profile-Pic`: URL to user's profile picture

## Example Usage

```bash
# Basic usage
./tsp --upstream=http://localhost:8080

# With auth key and hostname specified
./tsp --upstream=http://localhost:3000 --tailscale-hostname=myapp --tailscale-auth-key=tskey-auth-xxxxx
```

## Docker Compose Example

```yaml
services:
  tsp:
    image: ghcr.io/greboid/tsp:latest
    environment:
      - UPSTREAM=http://app:8080
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
    ports:
      - "8080:80"
    restart: unless-stopped
```
