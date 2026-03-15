FROM golang:1.24-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /demo-hostapp ./cmd/demo-hostapp/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /demo-hostapp /usr/local/bin/demo-hostapp
EXPOSE 3001
ENTRYPOINT ["demo-hostapp"]
