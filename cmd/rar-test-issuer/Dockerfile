# Build from repo root: docker build -f cmd/rar-test-issuer/Dockerfile -t rar-test-issuer .
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY . .
WORKDIR /src/cmd/rar-test-issuer
RUN CGO_ENABLED=0 GOWORK=off go build -o /rar-test-issuer .

FROM alpine:3.21
COPY --from=builder /rar-test-issuer /usr/local/bin/
EXPOSE 8181
CMD ["rar-test-issuer"]
