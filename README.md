# SOC Automation Lab — SOAR Pipeline

A hands-on SOC automation project that replicates a real Tier 1 SOC analyst workflow — from alert detection to AI-powered enrichment to active firewall response — built entirely in a home lab environment.

---

## Data Flow

Kali (attacker) → Suricata IDS/IPS (detects) → Splunk SIEM (stores) → soc_playbook.py (ingests) → Groq AI (enriches) → iptables (blocks) → cyber_soar.log (audits)

---

## Pipeline Stages

| Stage | Name | What it does |
|---|---|---|
| 0 | Startup Check | Validates Groq API model is live before running |
| 1 | Ingest | Queries Splunk REST API for Suricata alerts (index=suricata) |
| 2 | Enrich | Sends alert to Groq LLM — returns MITRE ATT&CK ID, severity, confidence, recommended action |
| 3 | Parse | Extracts JSON from LLM response with a regex fallback on failure |
| 4 | Decide & Act | Auto-blocks IP via iptables if severity ≥ 7, confidence ≥ 80%, action = block |
| 5 | Audit | Writes full JSON log to cyber_soar.log |

---

## Active Defense Logic

If all three conditions are met simultaneously:
- Severity score ≥ 7
- Confidence score ≥ 80%
- Recommended action contains "block"

→ The attacker IP is blocked via `iptables -A INPUT` and auto-removed after 10 minutes using a background thread with `time.sleep()`.

---

## Tech Stack

- **Splunk Enterprise** — SIEM, alert storage, REST API
- **Suricata IDS/IPS** — Network intrusion detection with custom rules
- **Groq API (LLM)** — AI-powered threat enrichment (`openai/gpt-oss-20b`)
- **iptables** — Linux firewall for active IP blocking
- **Python 3** — Automation script (`requests`, `urllib3`, `re`)
- **MITRE ATT&CK Framework** — Threat classification

---

## Lab Environment

| Role | OS | IP |
|---|---|---|
| Attacker | Kali Linux VM | 192.168.56.101 |
| IDS/IPS | Ubuntu VM (Suricata) | 192.168.56.102 |
| SIEM | Windows Host (Splunk) | 192.168.56.1 |

---

## Setup & Usage

```bash
export GROQ_API_KEY="your_groq_api_key"
sudo -E python3 soc_playbook.py
```

> Note: Splunk must be running at port 8089. Suricata must be forwarding logs via Universal Forwarder.

---

## Sample Output

```
✅ Model 'openai/gpt-oss-20b' confirmed active.

[SIEM INGEST] Alert Triggered: SYN Packet Detected from 192.168.56.101 | Event Count: 4283

[SOAR THREAT INTELLIGENCE ENRICHMENT]
  Attack Type   : SYN Flood (Denial of Service)
  MITRE ATT&CK  : T1499
  Impact Scope  : Network availability and service disruption
  AI Confidence : 90%
  Triaged Severity: 9/10
  Rec. Action   : Block source IP 192.168.56.101 at firewall, enable SYN cookies
  Analyst Note  : 4283 SYN packets in 24 hours from a single internal IP

[ORCHESTRATION ENGINE] Risk thresholds met. Isolating 192.168.56.101...
✅ Active Defense Rule Engaged. Auto-cleanup in 10 min.
✅ Incident logged to: cyber_soar.log
```

## Skills Demonstrated

- SIEM querying via Splunk REST API
- LLM integration for security enrichment (Groq API)
- MITRE ATT&CK mapping
- Active defense automation (iptables via Python subprocess)
- Python scripting and JSON parsing with regex
- Structured audit logging

---

## Author

Poojasri T S — B.E. CSE (Cybersecurity), SRM Madurai College for Engineering and Technology
