FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /api ./cmd/api
RUN CGO_ENABLED=0 go build -o /provision ./cmd/provision
FROM alpine:3.21
COPY --from=build /api /api
COPY --from=build /provision /provision
EXPOSE 8080
CMD ["/api"]
