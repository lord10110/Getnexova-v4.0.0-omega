# GetNexova v4.0.0 OMEGA
# Complete Installation Guide — Windows 11 + Docker
# ═══════════════════════════════════════════════════

This guide takes you from a fresh Windows 11 machine to a running
GetNexova scan in Docker. Every step is explicit. No assumptions.

---

## TABLE OF CONTENTS

1. [Prerequisites — What to install on Windows 11](#1-prerequisites)
2. [Download and configure GetNexova](#2-download-and-configure)
3. [Build and run with Docker](#3-build-and-run-with-docker)
4. [All commands reference](#4-all-commands)
5. [How the pipeline works](#5-how-the-pipeline-works)
6. [Where everything is stored](#6-where-everything-is-stored)
7. [Troubleshooting](#7-troubleshooting)
8. [Work plan (weeks 1-4)](#8-work-plan) ← YOUR ROADMAP

---

## 1. PREREQUISITES

You need three things installed on Windows 11:

### 1A. Install Docker Desktop

1. Go to https://www.docker.com/products/docker-desktop/
2. Download "Docker Desktop for Windows"
3. Run the installer
4. **IMPORTANT**: When asked, select "Use WSL 2 instead of Hyper-V" ← check this box
5. Restart your computer when prompted
6. After restart, open Docker Desktop
7. Wait for it to say "Docker Desktop is running" (green icon in system tray)

**Verify it works** — open PowerShell and type:
```powershell
docker --version
# Should show: Docker version 27.x.x or similar

docker compose version
# Should show: Docker Compose version v2.x.x
```

### 1B. Install Git

1. Go to https://git-scm.com/download/win
2. Download and run the installer
3. Use all default settings (just click Next through everything)

**Verify:**
```powershell
git --version
# Should show: git version 2.x.x
```

### 1C. Get at least one FREE API key

You need this for the AI analysis features. Both are free:

| Provider | Sign up at | What you get |
|----------|-----------|--------------|
| **Groq** | https://console.groq.com | Free API key, fast Llama 3.1 |
| **Gemini** | https://aistudio.google.com | Free API key, Gemini Flash |

**Recommended**: Get BOTH keys (takes 2 minutes each) for redundancy.

After signing up, copy your API key. You'll need it in Step 2.

---

## 2. DOWNLOAD AND CONFIGURE

Open **PowerShell** (search "PowerShell" in Start menu) and run these commands:

### 2A. Clone the project

```powershell
cd $HOME\Desktop
git clone https://github.com/lord10110/GetNexova.git
cd GetNexova
```

### 2B. Create your configuration file

```powershell
Copy-Item .env.example .env
notepad .env
```

Notepad will open. Edit these lines (replace with YOUR keys):

```
GROQ_API_KEY=gsk_paste_your_groq_key_here
GEMINI_API_KEY=paste_your_gemini_key_here
ANTHROPIC_API_KEY=
MAX_COST_PER_RUN=5.0
```

Save the file (Ctrl+S) and close Notepad.

### 2C. Create the logs directory

```powershell
mkdir logs -ErrorAction SilentlyContinue
```

**That's it for configuration.** Docker handles all tool installation automatically.

---

## 3. BUILD AND RUN WITH DOCKER

### 3A. Build the containers (first time only — takes 5-10 minutes)

```powershell
docker compose build
```

This downloads Python, Go, and installs all security tools (subfinder, httpx, nuclei, dalfox, nmap, nikto, gitleaks, semgrep, etc.) inside the containers. You don't need to install any of these on Windows.

**What's happening during the build:**
- Main container: Python 3.12 + Go 1.22 + subfinder + httpx + nuclei + dalfox
- Advanced tools container: nmap + nikto + gitleaks + semgrep + wapiti + dnsrecon + wpscan

### 3B. Start the advanced tools container (background)

```powershell
docker compose up -d advanced-tools
```

Wait 30 seconds for it to finish starting, then verify:

```powershell
docker compose ps
```

You should see `getnexova-advanced-tools` with status "healthy".

### 3C. Run your first scan!

**Quick test scan (2-5 minutes):**
```powershell
docker compose run nexova -t example.com --mode quick --no-ai
```

**Standard scan with AI (15-30 minutes):**
```powershell
docker compose run nexova -t YOUR-TARGET.com --mode standard
```

**Deep scan with all tools (30-90 minutes):**
```powershell
docker compose run nexova -t YOUR-TARGET.com --mode deep
```

### 3D. View your reports

Reports are saved inside the Docker volume. To copy them to your Desktop:

```powershell
# List what reports were generated
docker compose run nexova --stats

# Copy reports out of Docker to your Desktop
docker cp getnexova-engine:/app/reports/ $HOME\Desktop\getnexova-reports\
```

Or mount a local folder for reports (add this to docker-compose.yml under nexova → volumes):
```yaml
- ./my-reports:/app/reports
```

Then reports appear directly in `GetNexova\my-reports\`.

---

## 4. ALL COMMANDS

Run all these from inside the `GetNexova` folder in PowerShell.

### Scanning

```powershell
# Quick scan (subdomains + HTTP probe only)
docker compose run nexova -t target.com --mode quick

# Standard scan (recommended default)
docker compose run nexova -t target.com --mode standard

# Deep scan (comprehensive — uses advanced tools container)
docker compose run nexova -t target.com --mode deep

# Scan without AI analysis (tools only — no API key needed)
docker compose run nexova -t target.com --no-ai

# Specific report format
docker compose run nexova -t target.com --report-format html
docker compose run nexova -t target.com --report-format json

# Exclude subdomains from scope
docker compose run nexova -t target.com --exclude staging.target.com dev.target.com

# Set budget limit for AI calls
docker compose run nexova -t target.com --max-cost 2.0

# Resume an interrupted scan
docker compose run nexova -t target.com --resume

# Verbose output (debug)
docker compose run nexova -t target.com -v
```

### Utility

```powershell
# Check which tools are installed inside the container
docker compose run nexova --health-check

# View knowledge base statistics
docker compose run nexova --stats

# Show version
docker compose run nexova --version
```

### Docker management

```powershell
# Start advanced tools in background
docker compose up -d advanced-tools

# Start with local Ollama LLM
docker compose --profile local-llm up -d

# Stop all containers
docker compose down

# Rebuild after code changes
docker compose build --no-cache

# View container logs
docker compose logs -f nexova
docker compose logs -f advanced-tools

# Check container health
docker compose ps
```

---

## 5. HOW THE PIPELINE WORKS

When you run a scan, GetNexova executes 20 phases in sequence:

```
PHASE  WHAT HAPPENS                           MODE
─────  ──────────────────────────────────────  ────────────
 1     Initialize + check tool health          all
 2     Configure scope boundaries              all
 3     Subdomain enumeration (subfinder)       all
 4     HTTP probing (httpx → live hosts)       all
 5     URL discovery (gau/waybackurls/katana)  standard+deep
 6     Vulnerability scan (nuclei)             all
 7     XSS scanning (dalfox)                   standard+deep
 8     Web server scan (nikto)                 deep
 9     Network scan (nmap)                     deep
10     Shuvon scanners (IDOR/OAuth/Race/       standard+deep
       GraphQL/endpoint probing — REAL HTTP)
11     Plugin scanners                         all
12     Advanced tools (Docker container)       deep
13     Dual Validation (4-gate system)         all (with AI)
14     CVSS v3.1 scoring                       all (with AI)
15     Chain + Correlation analysis            all
16     Screenshot capture                      all
17     PoC generation (curl/Python scripts)    all
18     Report generation (HTML/MD/JSON)        all
19     Knowledge base update + learning        all
20     Notifications (Discord/Slack/Telegram)  all
```

### Data flow between phases:

```
subfinder → writes subdomains.txt
                ↓
httpx → reads subdomains.txt → writes live_hosts.txt + detects technologies
                ↓
nuclei → reads live_hosts.txt → vulnerability findings
                ↓
gau/katana → discovers URLs → writes urls.txt
                ↓
dalfox → reads urls.txt (URLs with ?param=) → XSS findings
                ↓
Shuvon → reads urls.txt → sends REAL HTTP requests → confirmed findings
                ↓
All findings → Dual Validation (4 gates) → validated findings
                ↓
validated → CVSS scoring → Chain analysis → Screenshots → PoCs → Reports
```

---

## 6. WHERE EVERYTHING IS STORED

Inside the Docker container:

```
/app/reports/              ← Generated reports (HTML, Markdown, JSON)
/app/data/                 ← Knowledge base, cost history
/app/data/workspaces/      ← Per-target scan data
  target_com/
    scan_data/
      subdomains.txt       ← Discovered subdomains
      live_hosts.txt       ← Confirmed live hosts
      urls.txt             ← Discovered URLs
      httpx_output.jsonl   ← Full httpx results
    pocs/                  ← Generated PoC scripts
    screenshots/           ← Visual evidence
    checkpoints/           ← Resume data
/app/logs/                 ← Detailed JSON logs
```

On your Windows machine:

```
GetNexova\
  .env                     ← Your API keys (DO NOT commit to git)
  logs\                    ← Log files (mounted from container)
  docker-compose.yml       ← Docker configuration
```

---

## 7. TROUBLESHOOTING

### "Docker Desktop is not running"
→ Open Docker Desktop from Start menu. Wait for the green whale icon.

### "docker compose build" fails
```powershell
# Clean everything and retry
docker system prune -a
docker compose build --no-cache
```

### "Cannot connect to advanced-tools"
```powershell
# Make sure it's running and healthy
docker compose up -d advanced-tools
docker compose ps
# Wait 30 seconds, then check:
docker compose logs advanced-tools
```

### "All models failed" (AI errors)
→ Check your API keys in `.env`
→ Make sure you have internet access
→ Try with `--no-ai` flag to skip AI and use tools only

### Scan is very slow
```powershell
# Use quick mode for initial testing
docker compose run nexova -t target.com --mode quick

# Or increase timeout
docker compose run nexova -t target.com --timeout 600
```

### "No reports found"
Reports are inside the Docker volume. Extract them:
```powershell
docker cp getnexova-engine:/app/reports/ .\my-reports\
```

### Windows Defender blocks Docker
→ Add Docker Desktop to Windows Defender exclusions:
  Settings → Update & Security → Windows Security → Virus & threat protection → Manage settings → Exclusions → Add exclusion → Folder → `C:\Program Files\Docker`

### How to see what tools are installed
```powershell
docker compose run nexova --health-check
```

---

## 8. WORK PLAN

This is your week-by-week roadmap to go from installation to actively earning bounties.

### ═══ WEEK 1: Setup & First Scans ═══

**Day 1-2: Installation**
- [ ] Install Docker Desktop on Windows 11
- [ ] Install Git
- [ ] Clone GetNexova repository
- [ ] Get free API keys (Groq + Gemini)
- [ ] Configure `.env` file
- [ ] Run `docker compose build` (one-time, takes 10 min)
- [ ] Run `docker compose run nexova --health-check`

**Day 3-4: First scans**
- [ ] Run `--mode quick --no-ai` on example.com (test the pipeline)
- [ ] Run `--mode quick` on 3 different authorized targets
- [ ] Check `logs/` directory for any errors
- [ ] Read the generated HTML report — understand the format

**Day 5-7: Standard scans**
- [ ] Run `--mode standard` on your best Intigriti/YesWeHack target
- [ ] Review the Markdown report — is it submission quality?
- [ ] Check the PoC scripts — do the curl commands work?
- [ ] Note what the AI classified as false positive vs. valid

### ═══ WEEK 2: Tune & Submit ═══

**Day 8-9: Deep scanning**
- [ ] Start advanced tools: `docker compose up -d advanced-tools`
- [ ] Run `--mode deep` on your primary target
- [ ] Compare deep vs standard results — what did deep find extra?
- [ ] Review the diff report (compares current vs previous scan)

**Day 10-11: Authentication**
- [ ] If your target requires login, get session cookies from browser (F12 → Network → Copy cookie header)
- [ ] Run: `docker compose run nexova -t target.com --auth-cookies "session=abc123"`
- [ ] Compare authenticated vs unauthenticated scan results

**Day 12-14: Submit findings**
- [ ] Pick your best validated findings (severity: high or critical)
- [ ] Use the generated Markdown report as your submission text
- [ ] Attach screenshots from the `screenshots/` directory
- [ ] Include the PoC curl commands from `pocs/` directory
- [ ] Submit to the bug bounty platform
- [ ] Note which findings are accepted/rejected — this feedback improves your process

### ═══ WEEK 3: Scale & Optimize ═══

**Day 15-17: Multiple targets**
- [ ] Run standard scans on 5+ different program targets
- [ ] Compare diff reports between scan runs (new findings highlighted)
- [ ] Review the knowledge base: `docker compose run nexova --stats`
- [ ] Check which tools produce the most valid findings for your targets

**Day 18-19: Notifications**
- [ ] Set up Discord webhook (create a private channel for alerts)
- [ ] Add `DISCORD_WEBHOOK=https://discord.com/api/webhooks/...` to `.env`
- [ ] Rebuild: `docker compose build`
- [ ] Run a scan — you should get Discord notifications for findings

**Day 20-21: Optimization**
- [ ] Identify which Shuvon scanners find the most for your target types
- [ ] Try different modes on different targets to find optimal settings
- [ ] Check AI cost usage — are you staying within budget?

### ═══ WEEK 4+: Ongoing Operations ═══

**Daily routine (15 minutes):**
- [ ] Run `--mode standard` on your active targets
- [ ] Check diff reports for new findings
- [ ] Submit any new valid findings immediately

**Weekly deep dive (1-2 hours):**
- [ ] Run `--mode deep` on primary targets
- [ ] Review knowledge base statistics
- [ ] Check for new programs on Intigriti/YesWeHack
- [ ] Run quick scans on new programs to identify low-hanging fruit

**Key principle:** First reporter wins. Run scans frequently and submit quickly.

---

## QUICK START SUMMARY (copy-paste these)

```powershell
# ONE-TIME SETUP (do this once)
cd $HOME\Desktop
git clone https://github.com/lord10110/GetNexova.git
cd GetNexova
Copy-Item .env.example .env
notepad .env                          # ← Add your API keys, save, close
mkdir logs -ErrorAction SilentlyContinue
docker compose build                  # ← Takes 5-10 minutes

# EVERY SCAN SESSION
docker compose up -d advanced-tools   # ← Start advanced tools (background)
docker compose run nexova -t TARGET.com --mode standard

# VIEW REPORTS
docker cp getnexova-engine:/app/reports/ .\my-reports\
```

---

*GetNexova v4.0.0 OMEGA — Built for responsible security research*
*Only scan targets within your authorized bug bounty program scope.*
