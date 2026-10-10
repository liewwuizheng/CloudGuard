# 🛡️ CloudGuard: Autonomous FinOps Control Plane

![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B.svg)
![Architecture](https://img.shields.io/badge/Architecture-Resilient%20Event%20Driven-8A2BE2)
![Hackathon](https://img.shields.io/badge/Status-Hackathon_MVP-success.svg)

> **In the AI era, an infinite loop script can burn $5,000 in OpenAI or AWS EC2 costs in 10 minutes.** Traditional cost explorers have a 12-hour delay. CloudGuard is not a dashboard; it is an **Autonomous Fire Extinguisher** for your cloud assets.

CloudGuard is an out-of-band, real-time FinOps governance platform. It autonomously monitors cloud telemetry, detects runaway billing anomalies via Dynamic EMA (Exponential Moving Average), and strictly enforces API gateway rate limits using a robust circuit breaker.

---

## ⚡ Key Architectures: The 3-Tier Defense Matrix

### Tier 1: Detection & Policy Evaluation
* **Real-Time Telemetry Stream**: High-frequency polling tracks actual API consumption against historical baselines.
* **15-Second Defense Buffer**: When a 450% cost spike is detected, the system triggers a 15-second grace countdown, giving human operators a "golden window" to intervene before the AI takes over.

### Tier 2: Dual-Mode Circuit Breaking
* **Autonomous AI Fail-Safe**: If the 15-second buffer expires without human intervention, the Autopilot Engine instantly seals the API gateway (`is_stopped = True`), stopping the bleeding.
* **Manual Override**: Operators retain absolute control via the "🚨 Execute Instant Stop-Loss" protocol.

### Tier 3: Resilient Transport (High Availability)
* **Exponential Backoff Retry**: Network jitter won't cause mitigation to fail. The gateway adapter retries execution up to 3 times with exponentially increasing delays.
* **Dead-Letter Queue (DLQ)**: If all retries fail, events are dumped into a secure DLQ, immediately triggering a P0 Alert (e.g., PagerDuty). 

---

## 🍌 The "Banana Factory" HA Model

To understand our **Exponential Backoff & Resilient Retry Mechanism**, imagine a banana factory:

```text
🍌 [ Infinite Banana Feeder ] ---Normal: 1/hr---> 🐒 Regular User
       |
       +---BUG DETECTED: 450/sec---> 🦍 CRAZY GORILLA (Cost Spike!)
                 |
                 v
⏱️ [ 15-Second Warning Buffer ]
                 |
        +--------+--------+
        |                 |
🤖 AI Auto-Lock       🚨 Manual Override
(Zero-Touch)          (Instant Stop-Loss)
        |                 |
        +--------+--------+
                 |
                 v
🏃 Guard runs to lock the vault door (Gateway API Call)
                 |
        Slips on a Banana Peel? (Network Timeout / Partition)
        +--------+--------+
        |                 |
     [ YES ]           [ NO ] ---> 🔒 VAULT LOCKED. (Saved $9,000)
        |
  🔄 Retry Protocol
  (Wait 1s -> 2s -> 4s)
        |
  If 3 retries completely fail? 
        |
  📦 Push to DLQ + ☎️ P0 PagerDuty Alert to CEO

```
---

## 🛠️ Tech Stack & Security
Frontend/State Machine: Streamlit, Plotly (Real-time async unblocked rendering via st_autorefresh)

Data Processing: Pandas, SQLite3

Audit Exports: ReportLab (PDF), python-docx (Word)

Security Principle (Out-of-band): CloudGuard relies strictly on the Principle of Least Privilege. Vault credentials are AES-256 encrypted. We do not proxy business traffic; zero latency overhead is added to the data plane. (Note: Local cloudguard_users.db is strictly .gitignored to prevent credential leaks).

---

## 🚀Installation and Quick Start
### 1. Clone the repository
```bash
git clone [https://github.com/your-username/CloudGuard.git](https://github.com/your-username/CloudGuard.git)
cd CloudGuard
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Control Plane
```bash
streamlit run app.py
```

### 4. Demo Walkthrough

#### 1.Register/Login to the portal.
#### 2.Create an Organization Workspace.
#### 3.Open the sidebar Secure Credential Vault, select an API, and click ⚡ Quick Demo Preset to inject sandbox credentials.
#### 4.Watch the autonomous telemetry stream advance and test the Instant Stop-Loss failsafe!
