FROM golang:1.23.0-alpine3.20

WORKDIR /app

COPY . .

# Set the correct architecture for google cloud run
ENV GOARCH=amd64

# Download and install the dependencies
RUN go get -d -v ./...

# Build the Go app
RUN go build -o api .

EXPOSE 8080

ENTRYPOINT ["./api"]
