FROM golang:1.23.3-bookworm as builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . ./
RUN go install github.com/go-task/task/v3/cmd/task@latest
RUN task build
RUN mkdir -p -v /data/gotrxx 

FROM gcr.io/distroless/base-debian11:nonroot
WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /app/bin/gotrxx /app/gotrxx
COPY --from=builder --chown=nonroot:nonroot /data/gotrxx /data/gotrxx 
USER nonroot:nonroot
CMD ["/app/gotrxx"]