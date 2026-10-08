# Cloudfarms Temporal server image: the upstream server with Cloudfarms JWT authorization (cmd/server/cloudfarms_auth.go).
# Built from the repository root:
#   docker build -f docker/cloudfarms/server.Dockerfile -t registry.cloudfarms.online/temporal/server:<tag> .
# The runtime stage is upstream's docker/targets/server.Dockerfile; only the binary is built here instead of by
# goreleaser, the same way `make temporal-server` builds it.

ARG GO_TAG=1.26-alpine
ARG ALPINE_TAG=3.24.1

FROM golang:${GO_TAG} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -tags disable_grpc_modules -o /out/temporal-server ./cmd/server

FROM alpine:${ALPINE_TAG}

RUN apk add --no-cache \
    ca-certificates \
    tzdata && \
    apk upgrade --no-cache zlib libcrypto3 libssl3 && \
    addgroup -g 1000 temporal && \
    adduser -u 1000 -G temporal -D temporal

COPY --from=build --chmod=755 /out/temporal-server /usr/local/bin/
COPY --chmod=755 ./docker/scripts/sh/entrypoint.sh /etc/temporal/entrypoint.sh

WORKDIR /etc/temporal
USER temporal

CMD [ "/etc/temporal/entrypoint.sh" ]
