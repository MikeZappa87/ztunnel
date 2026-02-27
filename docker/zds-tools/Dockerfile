# Dockerfile for zds-client and zds-server tools
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the pre-built binaries
COPY zds-client /usr/local/bin/zds-client
COPY zds-server /usr/local/bin/zds-server

RUN chmod +x /usr/local/bin/zds-client /usr/local/bin/zds-server

# Default to running zds-server
ENTRYPOINT ["/usr/local/bin/zds-server"]
CMD ["--help"]
