# syntax=docker/dockerfile:1.7
#
# zvm: the CLI, which also runs the devnet faucet (`zvm faucet`).
#
#   docker build -t zvm .

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/zvm ./cmd/zvm

FROM alpine:3.22
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/zvm /usr/local/bin/zvm
ENTRYPOINT ["zvm"]
