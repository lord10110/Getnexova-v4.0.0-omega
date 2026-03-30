# ════════════════════════════════════════════════════════
# GetNexova v4.0.0 OMEGA — Main Container (Fixed)
# ════════════════════════════════════════════════════════
# Stage 1: Build Go tools
# Stage 2: Copy to slim Python image
# ════════════════════════════════════════════════════════

# ─── Stage 1: Build Go binaries ───────────────────────
FROM golang:1.22-bookworm AS go-builder

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/hahwul/dalfox/v2@latest

# ─── Stage 2: Final image ─────────────────────────────
FROM python:3.12-slim

LABEL maintainer="GetNexova Team"
LABEL version="4.0.0"
LABEL description="GetNexova Bug Bounty Automation Platform"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    jq \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/dalfox /usr/local/bin/

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Working directory
WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create required directories
RUN mkdir -p data reports logs memory/store

# Default command
ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]
