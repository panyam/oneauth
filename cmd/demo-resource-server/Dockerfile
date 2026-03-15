FROM golang:1.24-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /demo-resource-server ./cmd/demo-resource-server/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /demo-resource-server /usr/local/bin/demo-resource-server
EXPOSE 4001
ENTRYPOINT ["demo-resource-server"]
