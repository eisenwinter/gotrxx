FROM golang:1.19-buster as builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . ./
RUN go build -v -o gotrxx
RUN mkdir -p -v /data/gotrxx 

FROM gcr.io/distroless/base-debian11:nonroot
WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /app/gotrxx /app/gotrxx
COPY --from=builder --chown=nonroot:nonroot /data/gotrxx /data/gotrxx 
USER nonroot:nonroot
CMD ["/app/gotrxx"]