# build stage
FROM golang:1.19-alpine3.16 AS builder
WORKDIR /app
COPY . .
RUN apk add --no-cache git \
    && go mod download \
    && go build -o ./out/dist cmd/main.go

# production stage
FROM alpine:3.16
COPY --from=builder /app/out/dist /app/
WORKDIR /app
EXPOSE 50051
CMD ["./dist"]
