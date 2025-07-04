FROM golang:1.24.2-alpine AS builder

WORKDIR /app
COPY . .
RUN go build -o /app/authservice ./cmd

FROM alpine:latest
WORKDIR /app

RUN mkdir -p /app/configs

COPY --from=builder /app/authservice .
COPY --from=builder /app/configs/dev.yml /app/configs/dev.yml

EXPOSE 8080
CMD ["./authservice"]