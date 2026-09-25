// C2 Sentinel - Popup Logic

const BACKEND_URL = "http://127.0.0.1:8000";

// DOM Elements
const connBadge = document.getElementById("connBadge");
const connText = document.getElementById("connText");
const valPackets = document.getElementById("valPackets");
const valPPS = document.getElementById("valPPS");
const valThreats = document.getElementById("valThreats");
const engineMode = document.getElementById("engineMode");
const alertsList = document.getElementById("alertsList");
const alertCountBadge = document.getElementById("alertCountBadge");
const btnOpenDashboard = document.getElementById("btnOpenDashboard");
const btnToggleSim = document.getElementById("btnToggleSim");

document.addEventListener("DOMContentLoaded", () => {
  fetchRecentData();
  const pollInterval = setInterval(fetchRecentData, 1500);

  // Clear interval when popup closes
  window.addEventListener("unload", () => clearInterval(pollInterval));

  // Open Full Dashboard button
  btnOpenDashboard.addEventListener("click", () => {
    chrome.tabs.create({ url: "http://localhost:8000" });
  });

  // Toggle Simulation button
  btnToggleSim.addEventListener("click", async () => {
    try {
      btnToggleSim.textContent = "⏳ Updating...";
      const res = await fetch(`${BACKEND_URL}/api/simulator/toggle`, { method: "POST" });
      const data = await res.json();
      btnToggleSim.textContent = data.is_simulating ? "⏹️ Stop C2 Attack" : "⚡ Simulate C2 Attack";
      fetchRecentData();
    } catch (err) {
      alert("Failed to reach C2 Sentinel backend. Ensure 'python run.py' is running.");
      btnToggleSim.textContent = "⚡ Simulate C2 Attack";
    }
  });
});

async function fetchRecentData() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/packets/recent`);
    if (!res.ok) throw new Error("Status " + res.status);

    const data = await res.json();
    const stats = data.stats || {};

    // Update connection status
    connBadge.className = "conn-badge online";
    connText.textContent = "Online";

    // Update metrics
    valPackets.textContent = (stats.total_packets || 0).toLocaleString();
    valPPS.innerHTML = `${stats.recent_pps || 0} <small>pps</small>`;
    valThreats.textContent = stats.threats_count || 0;

    // Update Engine Mode
    if (data.is_simulating) {
      engineMode.textContent = "C2 SIMULATION ACTIVE";
      engineMode.style.color = "#c084fc";
      btnToggleSim.textContent = "⏹️ Stop C2 Attack";
    } else if (data.is_sniffing) {
      engineMode.textContent = "SNIFFING LIVE";
      engineMode.style.color = "#34d399";
      btnToggleSim.textContent = "⚡ Simulate C2 Attack";
    } else {
      engineMode.textContent = "IDLE / READY";
      engineMode.style.color = "#94a3b8";
    }

    // Render threat alerts
    renderAlerts(data.packets || []);
  } catch (err) {
    connBadge.className = "conn-badge offline";
    connText.textContent = "Offline";
    engineMode.textContent = "BACKEND DISCONNECTED";
    engineMode.style.color = "#fb7185";
  }
}

function renderAlerts(packets) {
  // Filter threat packets
  const threats = packets.filter(p => ["CRITICAL", "HIGH", "MEDIUM"].includes(p.threat_level));
  alertCountBadge.textContent = threats.length;

  if (threats.length === 0) {
    alertsList.innerHTML = `
      <div class="empty-alerts">
        <div class="empty-icon">🛡️</div>
        <div>No active threats detected. Network clean.</div>
      </div>
    `;
    return;
  }

  // Show the last 4 threats
  const recentThreats = threats.slice(-4).reverse();
  alertsList.innerHTML = "";

  recentThreats.forEach(pkt => {
    const card = document.createElement("div");
    card.className = "alert-card";
    const sevClass = pkt.threat_level === "CRITICAL" ? "sev-CRITICAL" : "sev-HIGH";
    const reason = (pkt.threat_reasons && pkt.threat_reasons[0]) 
      ? pkt.threat_reasons[0] 
      : "Suspicious C2 activity";

    card.innerHTML = `
      <div class="alert-header">
        <span class="alert-flow">${escapeHtml(pkt.src_ip)} ➔ ${escapeHtml(pkt.dst_ip)}:${pkt.dst_port}</span>
        <span class="alert-sev ${sevClass}">${pkt.threat_level}</span>
      </div>
      <div class="alert-desc">${escapeHtml(reason)}</div>
      <div style="margin-top: 6px; display: flex; justify-content: space-between; align-items: center;">
        <span style="font-size: 8px; color: #64748b;">${pkt.dst_ip}</span>
        <button class="btn-block-ext" data-ip="${escapeHtml(pkt.dst_ip)}" data-reason="${escapeHtml(reason)}" style="background: rgba(168,85,247,0.25); border: 1px solid #a855f7; color: #d8b4fe; border-radius: 4px; padding: 2px 6px; font-size: 9px; font-weight: 700; cursor: pointer;">
          🛡️ Block IP
        </button>
      </div>
    `;

    const blockBtn = card.querySelector(".btn-block-ext");
    if (blockBtn) {
      blockBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const ip = blockBtn.dataset.ip;
        const reason = blockBtn.dataset.reason;
        blockBtn.textContent = "⏳ Blocking...";
        try {
          await fetch(`${BACKEND_URL}/api/block`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip, reason: "Extension Quick Block: " + reason })
          });
          blockBtn.textContent = "✅ Blocked";
          blockBtn.style.background = "rgba(16,185,129,0.3)";
          blockBtn.style.borderColor = "#10b981";
          blockBtn.style.color = "#34d399";
          fetchRecentData();
        } catch (err) {
          blockBtn.textContent = "❌ Failed";
        }
      });
    }

    // Click card opens dashboard
    card.style.cursor = "pointer";
    card.addEventListener("click", () => {
      chrome.tabs.create({ url: "http://localhost:8000" });
    });

    alertsList.appendChild(card);
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
