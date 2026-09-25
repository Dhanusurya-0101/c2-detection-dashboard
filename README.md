# C2 Sentinel - Real-Time C2 Detection Dashboard & Live Packet Sniffer

A real-time cybersecurity monitoring dashboard designed to detect Command and Control (C2) beaconing, DNS tunneling exfiltration, and suspicious egress traffic from live network packet streams.

---

## 🚀 Quick Start

From the project root directory:

```bash
python run.py
```

This will start the FastAPI backend server and automatically open the SOC dashboard at **http://localhost:8000** in your browser.

---

## 🔍 How Live Packet Capturing & Detection Works

### 1. Architecture Flow
1. **Network Layer**: Scapy sniffs live raw packets using Npcap on the selected network adapter (Wi-Fi, Ethernet, Loopback).
2. **Detection Engine (`backend/detector.py`)**:
   - **Periodic Beaconing Detector**: Computes inter-arrival time ($\Delta t$) statistics (mean, variance, jitter) across `(src_ip, dst_ip, dst_port)` flows. Flows with jitter $< 20\%$ are flagged as automated heartbeats (e.g., Cobalt Strike, Sliver).
   - **DNS Tunneling Exfiltration**: Calculates Shannon entropy of incoming DNS query labels. Queries with high entropy ($> 3.6$) or anomalous label lengths ($> 25$) are flagged for tunneling/exfiltration.
   - **Known C2 & Suspicious Ports**: Flags connections to ports commonly used by adversary frameworks (4444 Metasploit, 1337, 5555 Sliver, 31337 Back Orifice, etc.).
3. **WebSocket Stream (`/ws/packets`)**: Sends parsed packet objects and aggregated statistics in real-time.
4. **Web SOC Dashboard (`frontend/`)**:
   - Live auto-scrolling packet table with protocol filters and quick search.
   - Real-time throughput (Packets Per Second) line chart.
   - Protocol breakdown doughnut chart.
   - C2 Threat Alerts feed with risk scoring (0–100) and rationale.
   - Deep Packet Inspector modal with ASCII/Hex preview and entropy metrics.

---

## 🧪 Testing with the Built-in C2 Simulator

No active malware is required to test and demonstrate the system!
1. Open the dashboard at `http://localhost:8000`.
2. Click **"SIMULATE C2 ATTACK"** in the top navigation bar.
3. The backend will inject realistic synthetic traffic:
   - **Cobalt Strike HTTP Beacons**: 2-second heartbeats with slight jitter to an external IP.
   - **DNS Exfiltration Queries**: High-entropy base64 encoded chunks targeting a C2 domain.
   - **Metasploit Shell Pulses**: Traffic on port 4444.
   - **Benign Background Web Traffic**: Normal HTTPS and DNS requests.
4. Watch the charts update, the C2 Beaconing Alert trigger, and the Threat cards populate!

---

## 🛠 Project Structure

```
c2-detection-dashboard/
├── backend/
│   ├── app.py          # FastAPI application & WebSocket server
│   ├── detector.py     # C2 detection algorithms (Beaconing, DNS entropy, heuristics)
│   ├── sniffer.py      # Scapy live packet capture thread
│   └── simulator.py   # Synthetic C2 attack traffic generator
├── frontend/
│   ├── index.html      # Dark-themed Cyber SOC dashboard
│   ├── style.css       # SIEM styling, animations, and threat color codes
│   └── app.js          # WebSocket client, Chart.js updates, table buffering
├── extension/          # Chrome Extension (Manifest V3)
│   ├── manifest.json   # Extension configuration & permissions
│   ├── background.js   # Service worker: desktop alerts & badge counter
│   ├── icons/          # Extension toolbar icons (16x16, 48x48, 128x128)
│   └── popup/          # Mini SOC popup dashboard (HTML/CSS/JS)
├── run.py              # Launcher script
└── README.md
```

---

## 🧩 Installing the Chrome Extension

1. Open Google Chrome and type `chrome://extensions` in the URL bar.
2. Toggle on **"Developer mode"** in the top-right corner.
3. Click **"Load unpacked"** in the top-left corner.
4. Select the `extension` folder inside this project:
   `C:\Users\dhanu\.gemini\antigravity\scratch\c2-detection-dashboard\extension`
5. Pin the extension to your toolbar. You will now get real-time badge counts and native desktop alerts whenever high-risk C2 beaconing or DNS exfiltration is detected!

---

## 🔐 Permissions Note for Windows Live Sniffing
To sniff live traffic on physical network adapters (like Wi-Fi or Ethernet), Windows requires Administrator permissions so Npcap can access the raw network device. If running without Administrator rights, you can still test all detection features using the **Simulate C2 Attack** button or loopback capture!
