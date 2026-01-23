FROM golang:1.24-alpine

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o dashboard-app ./cmd/dashboard/main.go

EXPOSE 8080

CMD ["./dashboard-app"]