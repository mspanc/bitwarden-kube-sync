FROM golang:1.25-alpine3.22 AS builder
RUN apk add --no-cache build-base pkgconfig ca-certificates
ENV CGO_ENABLED=1
WORKDIR /app
COPY . .
RUN go mod download && go build -ldflags '-linkmode external -extldflags "-static -Wl,-unresolved-symbols=ignore-all"' -o bitwarden-kube-sync main.go

FROM alpine:3.22
COPY --from=builder /app/bitwarden-kube-sync /usr/local/bin/bitwarden-kube-sync
CMD ["/usr/local/bin/bitwarden-kube-sync"]
