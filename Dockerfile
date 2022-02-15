FROM docker.io/golang:1.17 as builder

RUN apt update; apt install ca-certificates
COPY . $GOPATH/src/github.com/aiven/allstar
WORKDIR $GOPATH/src/github.com/aiven/allstar

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/allstar ./cmd/allstar/...

FROM alpine:latest 
COPY --from=builder /go/bin/allstar /go/bin/allstar
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT [ "/go/bin/allstar" ]
