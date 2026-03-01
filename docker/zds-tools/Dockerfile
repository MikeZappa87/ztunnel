# Dockerfile for zds-client and zds-server tools
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy the pre-built binaries
COPY zds-client /usr/local/bin/zds-client
COPY zds-server /usr/local/bin/zds-server
COPY ztunnel-redirect-workload.sh /usr/local/bin/ztunnel-redirect-workload.sh

RUN chmod +x /usr/local/bin/zds-client /usr/local/bin/zds-server /usr/local/bin/ztunnel-redirect-workload.sh

# Default to running zds-server
ENTRYPOINT ["/usr/local/bin/zds-server"]
CMD ["--help"]
