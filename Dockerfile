# netrecon container image.
#
# Build:
#   docker build -t netrecon:latest .
#
# Run (raw-socket stages need NET_RAW/NET_ADMIN):
#   docker run --rm \
#     --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -v "$PWD/scope.txt:/scope/scope.txt:ro" \
#     -v "$PWD/results:/data/results" \
#     netrecon:latest scan --targets /scope/scope.txt --yes
#
# Without those capabilities netrecon still runs, degrading to nmap connect
# scans (see README: "Privileges").

FROM golang:1.22-bookworm AS gotools

ENV CGO_ENABLED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest


FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="netrecon" \
      org.opencontainers.image.description="Scope-enforced network reconnaissance for authorised engagements" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap \
      masscan \
      fping \
      libpcap0.8 \
      libcap2-bin \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gotools /go/bin/naabu /usr/local/bin/naabu
COPY --from=gotools /go/bin/nuclei /usr/local/bin/nuclei

WORKDIR /opt/netrecon
COPY pyproject.toml README.md ./
COPY netrecon ./netrecon
COPY configs ./configs
RUN pip install --no-cache-dir .

# Results land here; mount a volume over it to keep them.
WORKDIR /data
VOLUME ["/data"]

# The image runs as root so that masscan and nmap -sS work when the container
# is given NET_RAW. Drop to a non-root user if you only need connect scans:
#   docker run --user 65534:65534 ...
ENTRYPOINT ["netrecon"]
CMD ["--help"]
