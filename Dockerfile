FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/snmp-proxy ./cmd/snmp-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/snmp-proxy /usr/local/bin/snmp-proxy
EXPOSE 8443
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/snmp-proxy"]
