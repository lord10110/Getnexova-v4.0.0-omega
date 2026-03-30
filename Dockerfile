# ════════════════════════════════════════════════════════
# GetNexova v4.0.0 OMEGA — Main Container
# ════════════════════════════════════════════════════════
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

# Install Go for ProjectDiscovery tools
ENV GOPATH=/root/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
RUN wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz \
    && rm go1.22.4.linux-amd64.tar.gz

# Install core recon tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/hahwul/dalfox/v2@latest

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
