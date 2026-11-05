# IoTGuard Edge IDS Container
# Multi-stage Dockerfile for Raspberry Pi (ARM64) and Gateway Linux (x86_64)

FROM python:3.12-slim-bookworm AS base

# Install runtime system packages and nftables
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iproute2 \
    procps \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated unprivileged user for Least-Privilege Execution (Pillar 3: Security)
RUN groupadd -g 10001 iotguard && \
    useradd -u 10001 -g iotguard -m -s /bin/bash iotguard

WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy IoTGuard codebase
COPY --chown=iotguard:iotguard config/ /app/config/
COPY --chown=iotguard:iotguard iotguard/ /app/iotguard/
COPY --chown=iotguard:iotguard models/ /app/models/
COPY --chown=iotguard:iotguard api/ /app/api/
COPY --chown=iotguard:iotguard dashboard/ /app/dashboard/
COPY --chown=iotguard:iotguard scripts/ /app/scripts/
COPY --chown=iotguard:iotguard data/samples/ /app/data/samples/
COPY --chown=iotguard:iotguard cli.py /app/cli.py
COPY --chown=iotguard:iotguard README.md /app/README.md

# Create logs directory
RUN mkdir -p /app/logs && chown -R iotguard:iotguard /app/logs

# Set environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Default unprivileged user execution (CAP_NET_ADMIN granted via docker-compose)
USER iotguard

EXPOSE 8000 8501

ENTRYPOINT ["python", "cli.py"]
CMD ["api", "--host", "0.0.0.0", "--port", "8000"]
