# ════════════════════════════════════════════════════════
# GetNexova v4.0.0 OMEGA — Main Container
# ════════════════════════════════════════════════════════
# Single-stage build: download pre-built Go tool binaries
# directly to avoid Go toolchain version issues.
# ════════════════════════════════════════════════════════

FROM python:3.12-slim

LABEL maintainer="GetNexova Team"
LABEL version="4.0.0"
LABEL description="GetNexova Bug Bounty Automation Platform"

# ─── System dependencies ─────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    jq \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ─── Python app ──────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ─── Go tool versions (pinned for reproducibility) ───
# IMPORTANT: Binary downloads MUST come AFTER pip install
# because the Python httpx package installs an "httpx" CLI
# that would shadow the ProjectDiscovery httpx binary.
ENV SUBFINDER_VERSION=2.6.7
ENV HTTPX_VERSION=1.8.0
ENV NUCLEI_VERSION=3.3.7
ENV DALFOX_VERSION=2.9.3

# ─── Download pre-built Go binaries ──────────────────
# subfinder
RUN curl -sSfL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
    -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /tmp/subfinder \
    && mv /tmp/subfinder/subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm -rf /tmp/subfinder /tmp/subfinder.zip

# httpx (ProjectDiscovery — overwrites the Python httpx CLI)
RUN curl -sSfL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
    -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /tmp/httpx \
    && mv /tmp/httpx/httpx /usr/local/bin/httpx \
    && chmod +x /usr/local/bin/httpx \
    && rm -rf /tmp/httpx /tmp/httpx.zip

# nuclei
RUN curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei /tmp/nuclei.zip

# dalfox
RUN curl -sSfL "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_${DALFOX_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /tmp/ \
    && mv /tmp/dalfox /usr/local/bin/dalfox \
    && chmod +x /usr/local/bin/dalfox

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# ─── Copy project & finalize ─────────────────────────
COPY . .

# Create required directories
RUN mkdir -p data reports logs memory/store

ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]
