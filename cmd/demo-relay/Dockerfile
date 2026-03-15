FROM golang:1.24-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /demo-relay ./cmd/demo-relay/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /demo-relay /usr/local/bin/demo-relay
EXPOSE 4001
ENTRYPOINT ["demo-relay"]
