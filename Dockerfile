FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /exposure-check .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates jq
COPY --from=build /exposure-check /usr/local/bin/exposure-check
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
LABEL org.opencontainers.image.title="exposure-check" \
      org.opencontainers.image.description="Find what attackers can see before they do — open-source exposure scanner" \
      org.opencontainers.image.url="https://github.com/bariskececi/exposure-check" \
      org.opencontainers.image.source="https://github.com/bariskececi/exposure-check" \
      org.opencontainers.image.vendor="GNSAC" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["/usr/local/bin/exposure-check"]
