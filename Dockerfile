FROM golang:1.27-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /shipguard ./cmd/shipguard
# Only the rule definitions ship in the image, not the vulnerable test targets.
RUN mkdir /rules \
    && find rules \( -name '*.yaml' -o -name LICENSE -o -name README.md \) -print \
    | tar -cf - -T - | tar -xf - -C /rules

# Downloads the pinned scanners and fails the build on any checksum mismatch.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS scanners
ARG TARGETARCH
RUN apk add --no-cache curl
COPY versions.env /opt/versions.env
COPY scripts/install-scanners.sh /opt/scripts/install-scanners.sh
RUN sh /opt/scripts/install-scanners.sh "$TARGETARCH"

# Runs as root on purpose: GitHub Docker actions require it to access the
# workspace, and CI job images write outputs into root-owned clone directories.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache git ca-certificates \
    && git config --system --add safe.directory '*'
COPY --from=scanners /usr/local/bin/gitleaks /usr/local/bin/opengrep /usr/local/bin/osv-scanner /usr/local/bin/trivy /usr/local/bin/
COPY --from=builder /rules/rules /opt/shipguard/rules
COPY --from=builder /shipguard /usr/local/bin/shipguard
ENTRYPOINT ["shipguard"]
CMD ["run"]
