Markdown
# ForensixEML
**⚠️ AI Notice**

This is a vibe coded program but under human supervision. It was for a hackathon (Smart India Hackathon 2026) but could evolve into something new and improved. Something better.

---

ForensixEML is an advanced, offline-first email forensic analysis and threat detection platform. It combines deterministic heuristics with local, air-gapped AI models (DistilBERT and Qwen 1.5B) to provide enterprise-grade email triage, IOC extraction, and automated DFIR reporting.

## 💻 System Requirements

To ensure smooth operation of the local AI models, the following specifications are required:

*   **Code Editor:** Visual Studio Code (VS Code) is highly recommended for terminal management.
*   **Python:** Version 3.12 (Strict requirement for dependency compatibility).
*   **Hardware (Safe Zone):**
    *   **GPU:** Dedicated NVIDIA GPU with at least **6GB+ VRAM** (CUDA 12.4 compatible) to run both DistilBERT and Qwen 1.5B concurrently.
    *   **RAM:** 16GB+ System Memory.
    *   **Storage:** \~15GB of free disk space (~11GB required for PyTorch CUDA wheels and AI model weights).

---

## 🛠️ Installation Setup

The following instructions assume the use of Visual Studio Code on a Windows environment.

1. Open the cloned Git repository folder in VS Code.
2. Open a new Terminal (`Ctrl + ~`).
3. Run the following commands sequentially to build the virtual environment and install all dependencies:

```powershell
# 1. Create a Python 3.12 virtual environment
py -3.12 -m venv .venv

# 2. Allow execution of local scripts (Windows only)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 3. Activate the environment
.\.venv\Scripts\activate

# 4. Run the unified installer (Handles CUDA/CPU PyTorch, packages, and AI models)
python .\scripts\install.py
```
Note: The install.py script will prompt the user to confirm the ~11GB download for the necessary machine learning environments and local models.

---
# 🚀 How to Run the Platform
ForensixEML uses a decoupled architecture to prevent the UI from freezing during heavy AI processing. The UI and the background daemon must be run in separate terminals.
```powershell
# Terminal 1: Start the Web UI. Ensure the .venv is active, then run:
streamlit run app.py --server.address=0.0.0.0

# Terminal 2: Start the AI Automation script. Ensure the .venv is active, then run:
python .\scripts\ingestion_daemon.py

# Terminal 3 (Optional): Email Traffic Simulator.
# To generate live, synthetic forensic test cases (benign and malicious) for the system to process:
# Ensure the .venv is active, then run:
python .\scripts\traffic_simulator.py
```
---
# 🕹️ Operation Guide

Authentication: Log into the portal using the default credentials:
```
Username: admin
Password: sih2026
```
System Settings: Navigate to the Settings tab to toggle the Automated Ingestion Daemon on or off.

---

# Investigation Workbench

* Navigate to the Upload & Ingest tab to manually drop .eml files for analysis.
* If the traffic simulator is running, users can watch live .eml files being spooled and autonomously ingested by the AI.
* Then navigate to Workbench to get a complete overview of the email analysed.

> **⚠️ AI MODEL NOTE & GITHUB SIZE LIMITS:** 
> Due to GitHub's repository size limits, the pre-trained/fine-tuned weights for our local AI models (DistilBERT and Qwen) are not bundled directly in this repository. 
> 
> * **With AI Enabled:** The platform runs full semantic NLP threat narration and deep phishing classification.
> * **Without AI (Fallback Mode):** If model weights are missing, the system defaults to its **deterministic scoring engine**—relying entirely on header parsing, SPF/DKIM/DMARC authentication enforcement, MaxMind GeoIP telemetry, and rule-based regex heuristics to ensure uninterrupted forensic functionality.

---
# Fully Implemented (Production Baseline)
* NLP Phishing & Urgency Detection: Local DistilBERT inference evaluating body text and subject lines.
* Heuristic & Keyword Analysis: Rule-based regex scoring for urgency, financial triggers, and credential harvesting keywords.
* Deceptive Domain & Attachment Checks: Risky file extension validation and URL extraction routines.
* Header Parsing & RFC 5322 Ingestion: MIME decomposition of Received, Return-Path, Message-ID, and From fields.
* Authentication Enforcement: Full SPF alignment, DKIM signature verification, and DMARC policy validation.
* Origin IP Extraction & Hop Reconstruction: Parsing of earliest upstream relay candidates with an interactive visual Trace Map.
* IP Geolocation & ISP Profiling: Mapping of source IPs to country, region, organization, and basic ISP data.
* Domain Intelligence & Infrastructure Recon: Cached and live WHOIS queries, registrar verification, and DNS record (A, MX, TXT) lookups.
* Institutional Trust Whitelisting: Automated clearance logic for official domains (.gov.in, .nic.in) to reduce false positives.
* Analyst UI & Live Feed Workbench: Streamlit single-page application with dual-pane layout, case selection, and telemetry views.
* Audit-Ready Forensic PDF Reports: Export module generating structured DFIR summaries with automatic local timestamped backups.
* Database Persistence & Ingestion Daemon: Decoupled background service writing to SQLite utilizing Write-Ahead Logging (WAL mode).

---
# Partially Implemented
- Advanced Proxy, Tor & VPN Detection: Basic IP risk assignment implemented; missing real-time exit-node feed lookups.
- Campaign Correlation & Graph Intelligence: Correlation tab created; missing automated relationship clustering across cases.
- Evidentiary Chain-of-Custody & Privacy Masking: Immutable SHA-256 case hashing implemented; missing automated PII redaction and audit logs.

---
# 🔮 Future Scope & Roadmap
As the platform scales, the following architectural upgrades are planned:

- UI State RAM Optimization: Shift to Lazy Loading and Pagination. Currently, Streamlit holds cases in session state. The architecture will transition to reading dynamically from SQLite so the UI only holds the active case in RAM to prevent server crashes over time.
- Ingestion Resource Capping: Update the background folder-watcher daemon to use chunked processing (e.g., batches of 50 emails) and explicit Python garbage collection (gc.collect()) to prevent Out-Of-Memory (OOM) crashes during massive malicious mail spikes.
- AI Model Quantization (VRAM/RAM): Convert the heavy DistilBERT NLP model to an ONNX runtime or use INT8 quantization to shrink the memory footprint by up to 4x, allowing operation on standard servers without expensive GPUs.
- Binary Message Ingestion: Support for proprietary .msg parsing.
- Automated PII Redaction: Autonomous masking of phone numbers, national IDs, and specific names in exported logs for compliance, alongside a signed, tamper-evident audit ledger recording every analyst interaction.
- Autonomous Proxy Feeds: Integration of verified, offline threat-intelligence feeds for real-time Tor exit node and commercial VPN detection.
- Route Manipulation Detection: Advanced detection of forged internal hops injected by adversaries to conceal the true external sending MTA.
- Specialized Sub-Classifiers: Expanding beyond generic phishing to detect Business Email Compromise (BEC) edge cases (e.g., invoice payment diversion, executive impersonation) where standard malicious links and attachments are absent.
- Real-Time Push Notifications: Webhooks targeting SIEM/SOAR platforms or instant messaging channels for active cases requiring immediate network isolation.
