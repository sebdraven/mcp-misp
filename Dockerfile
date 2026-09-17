# Build stage.
FROM golang:1.27 AS build

WORKDIR /src

ARG VERSION=container
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Dependencies first, so a source-only change does not refetch the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off and a stripped binary: the runtime stage has no libc to link against.
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
        -o /out/mcp-misp ./cmd/mcp-misp

# Runtime stage.
#
# The image exists for the streamable-HTTP transport — a server someone can
# reach — rather than for the stdio process a desktop client spawns. It carries
# no data and no credentials: MISP_URL and MISP_KEY are supplied at run time.
#
# distroless static ships a CA bundle, which is load-bearing here: every call to
# the instance is HTTPS, and on scratch they would all fail on certificate
# errors.
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=container
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# org.opencontainers.image.source is what attaches the package to the repository
# on GHCR; without it the package has no visible provenance.
LABEL org.opencontainers.image.source="https://github.com/sebdraven/mcp-misp" \
      org.opencontainers.image.title="mcp-misp" \
      org.opencontainers.image.description="MCP server exposing a MISP instance to CTI workflows, with warninglist verdicts on every value returned" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=build /out/mcp-misp /usr/local/bin/mcp-misp

EXPOSE 8080

# The container listens on every interface and opts out of the loopback guard,
# because a process bound to 127.0.0.1 inside a container is unreachable through
# a published port. The loopback boundary moves to the host: publish this port
# as 127.0.0.1:8080:8080 and put a reverse proxy or `tailscale serve` in front.
# This server has no authentication of its own.
ENV MCP_TRANSPORT=http \
    MCP_HTTP_ADDR=0.0.0.0:8080 \
    MISP_ALLOW_PUBLIC_BIND=true

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mcp-misp"]
