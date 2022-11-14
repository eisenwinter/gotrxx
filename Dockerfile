FROM golang:1.19-buster as builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . ./
RUN go build -v -o gotrxx

FROM gcr.io/distroless/base-debian11:nonroot
WORKDIR /app
COPY --from=builder /app/gotrxx /app/gotrxx
USER nonroot:nonroot
CMD ["/app/gotrxx"]