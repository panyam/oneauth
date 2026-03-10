FROM golang:1.23-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /oneauth-server ./cmd/oneauth-server/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /oneauth-server /usr/local/bin/oneauth-server
COPY cmd/oneauth-server/oneauth-server.yaml /etc/oneauth/oneauth-server.yaml
EXPOSE 8080
ENTRYPOINT ["oneauth-server"]
CMD ["-config", "/etc/oneauth/oneauth-server.yaml"]
