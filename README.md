# Threat Intel Enrichment Tool

## Description
This script simulates the first step of alert triage in a SOC environment — 
enriching indicators of compromise (IOCs) with threat intelligence before 
making a triage decision. Built using VirusTotal's free API for home lab 
testing purposes.

## How It Works
1. **API Key** — A free VirusTotal account is required. The API key is stored 
   as an environment variable and never hardcoded in the script.
2. **IP List** — The script takes a list of IPs to investigate. For testing, 
   I used three IPs of varying risk levels:
   - `8.8.8.8` — Google's public DNS server (expected: clean)
   - `1.1.1.1` — Cloudflare's public DNS server (expected: clean)
   - `185.220.101.45` — Known Tor exit node (expected: malicious)
3. **Enrichment** — A for loop iterates over each IP and sends a GET request 
   to the VirusTotal API, retrieving how many of their 70+ threat intel engines 
   have flagged it as malicious, suspicious, or harmless.
4. **Triage Verdict** — Results are evaluated against a threshold to account 
   for false positives. A single engine flagging an IP is not enough to 
   classify it as malicious — context matters.

## Verdict Thresholds
| Malicious Count | Verdict |
|---|---|
| 0 | ✅ CLEAN |
| 1 - 5 | ⚠️ SUSPICIOUS |
| 6+ | 🚨 HIGH RISK |

## Security Concepts Demonstrated
- Threat intelligence enrichment
- IOC triage and false positive awareness
- API authentication via environment variables (secrets never in code)
- Automated security workflows / SOAR-adjacent thinking

## How To Run
1. Create a free account at virustotal.com and copy your API key
2. Set your API key as an environment variable:
```powershell
   $env:VT_API_KEY = "your_api_key_here"
```
3. Run the script:
```powershell
   python enrichment.py
```
## Future Improvements

### In Progress
- **Docker containerization** — packaging the script and its dependencies 
  into a portable container image for consistent execution across environments
- **Kubernetes deployment** — deploying the containerized script to a local 
  Kubernetes cluster using Minikube, mirroring how workloads are managed in 
  production environments.
- **Kubernetes Secrets** — migrating API key management from environment 
  variables to Kubernetes Secrets for more secure, production-grade 
  secret handling

### Planned
- **Scalability refactor** — abstracting the input layer using `*args`/`**kwargs` 
  to accept flexible input beyond hardcoded lists (files, stdin, API feeds)
- **URL and file hash lookups** — extending IOC support beyond IPs and domains 
  to include URLs and file hashes, covering the full range of VirusTotal's 
  threat intel capabilities
- **Defensive API error handling** — gracefully handling rate limit errors, 
  network timeouts, and unexpected API responses instead of crashing
- **Export options** — support for JSON output in addition to CSV, making 
  the triage report easier to pipe into SIEMs or ticketing systems