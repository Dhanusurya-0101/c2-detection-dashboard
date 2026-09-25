// C2 Sentinel - Background Service Worker (Manifest V3)

const BACKEND_URL = "http://127.0.0.1:8000";
let notifiedThreatIds = new Set();

// Setup periodic alarm to keep polling active even if service worker sleeps
chrome.runtime.onInstalled.addListener(() => {
  console.log("[C2 Sentinel] Extension installed successfully.");
  chrome.alarms.create("checkC2Status", { periodInMinutes: 0.05 }); // check every ~3-5 seconds
  checkBackendStatus();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "checkC2Status") {
    checkBackendStatus();
  }
});

// Also poll actively via interval when service worker is awake
setInterval(checkBackendStatus, 2500);

async function checkBackendStatus() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/packets/recent`);
    if (!res.ok) throw new Error("Backend not responding");

    const data = await res.json();
    const stats = data.stats || {};
    const threatsCount = stats.threats_count || 0;
    const isSniffing = data.is_sniffing;

    // 1. Update Badge
    if (threatsCount > 0) {
      chrome.action.setBadgeText({ text: String(threatsCount) });
      chrome.action.setBadgeBackgroundColor({ color: "#f43f5e" }); // Red
    } else if (isSniffing) {
      chrome.action.setBadgeText({ text: "LIVE" });
      chrome.action.setBadgeBackgroundColor({ color: "#10b981" }); // Emerald Green
    } else {
      chrome.action.setBadgeText({ text: "IDLE" });
      chrome.action.setBadgeBackgroundColor({ color: "#64748b" }); // Slate
    }

    // 2. Check for new High / Critical threats to notify
    if (data.packets && Array.isArray(data.packets)) {
      data.packets.forEach((pkt) => {
        if (["CRITICAL", "HIGH"].includes(pkt.threat_level)) {
          if (!notifiedThreatIds.has(pkt.id)) {
            notifiedThreatIds.add(pkt.id);
            triggerThreatNotification(pkt);
          }
        }
      });

      // Keep cache bounded
      if (notifiedThreatIds.size > 200) {
        notifiedThreatIds = new Set(Array.from(notifiedThreatIds).slice(-100));
      }
    }
  } catch (err) {
    // Backend is offline
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#475569" }); // Dark gray
  }
}

function triggerThreatNotification(pkt) {
  const reason = (pkt.threat_reasons && pkt.threat_reasons[0]) 
    ? pkt.threat_reasons[0] 
    : "Potential C2 Beaconing or anomalous egress flow detected.";

  const isBlocked = pkt.is_blocked;
  const notifOptions = {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: isBlocked ? `🛡️ Auto-Quarantined [${pkt.threat_level}]` : `🚨 C2 Threat Alert [${pkt.threat_level}]`,
    message: isBlocked 
      ? `QUARANTINED: ${pkt.src_ip} ➔ ${pkt.dst_ip}:${pkt.dst_port}\n${reason}\n[Action: Firewall Rule Injected]`
      : `${pkt.src_ip} ➔ ${pkt.dst_ip}:${pkt.dst_port}\n${reason}`,
    priority: 2,
    requireInteraction: false
  };

  chrome.notifications.create(`c2-threat-${pkt.id}`, notifOptions);
}

// Clicking a notification opens the full C2 Sentinel dashboard
chrome.notifications.onClicked.addListener((notificationId) => {
  chrome.tabs.create({ url: "http://localhost:8000" });
  chrome.notifications.clear(notificationId);
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "refreshStatus") {
    checkBackendStatus().then(() => sendResponse({ status: "checked" }));
    return true; // async response
  }
});
