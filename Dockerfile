# Use a minimal base image for the final image
FROM golang:1.21-alpine AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files to the working directory
COPY go.mod go.sum ./

# Download the Go module dependencies
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 go build -o cheap-switch-exporter

# Use a minimal base image for the final image
FROM scratch

# Copy the built binary from the previous stage
COPY --from=build /app/cheap-switch-exporter /cheap-switch-exporter

# Expose port 8080
EXPOSE 8080

# Set the entrypoint command for the Docker container
ENTRYPOINT ["/cheap-switch-exporter"]
