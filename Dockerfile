FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /exposure-check .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /exposure-check /usr/local/bin/exposure-check
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/usr/local/bin/exposure-check"]
