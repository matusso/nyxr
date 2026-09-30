FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /nyxr ./cmd/nyxr

FROM scratch
ARG VERSION=dev
ARG SOURCE=https://github.com/matusso/nyxr
LABEL org.opencontainers.image.source=$SOURCE \
      org.opencontainers.image.version=$VERSION
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /nyxr /nyxr
ENTRYPOINT ["/nyxr"]
