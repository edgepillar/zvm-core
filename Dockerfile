# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# zvm: the CLI, which also runs the devnet faucet (`zvm faucet`).
#
#   docker build -t zvm .

FROM golang:1.26.11-alpine3.24@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build
ENV GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    test "$(go env GOVERSION)" = go1.26.11 && \
    go mod download && \
    go mod verify
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/zvm ./cmd/zvm && \
    CGO_ENABLED=0 GOPROXY=off GOSUMDB=off go run ./tools/noticebundle \
    --binary /out/zvm --output /out/notices

FROM alpine:3.22.8@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
# The CLI uses Go HTTP clients. The base image provides BusyBox wget for shell probes.
RUN apk add --no-cache ca-certificates=20261020-r0
COPY --from=build /out/zvm /usr/local/bin/zvm
COPY --from=build /out/notices /usr/share/doc/zvm/notices
ENTRYPOINT ["zvm"]
