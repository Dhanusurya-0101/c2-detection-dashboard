// C2 Sentinel - Frontend Application Logic

// Auto-detect backend host (supports direct file://, VS Code Live Server, or FastAPI served host)
const isFileProtocol = window.location.protocol === 'file:' || !window.location.host;
const isLiveServer = window.location.port === '5500' || window.location.port === '3000' || window.location.port === '5173';
const BACKEND_HOST = (isFileProtocol || isLiveServer) ? '127.0.0.1:8000' : window.location.host;
const API_BASE = `${window.location.protocol === 'https:' ? 'https:' : 'http:'}//${BACKEND_HOST}`;
const WS_BASE = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${BACKEND_HOST}`;

// Global State
let socket = null;
let pollIntervalId = null;
let isSniffing = false;
let isSimulating = false;
let isPaused = false;
let autoScroll = true;
let selectedProtocol = 'ALL';
let selectedThreatFilter = 'ALL';
let searchQuery = '';

const MAX_TABLE_ROWS = 150;
let packetHistory = []; // stores recent packets
let packetQueue = [];   // queue for animation frame rendering
let alertsCount = 0;

// Chart Instances
let ppsChartInstance = null;
let protocolChartInstance = null;
const ppsHistory = Array(30).fill(0);
const ppsLabels = Array(30).fill('');

// Quarantine & Blocker State
let autoBlockEnabled = true;
let isSimulationMode = false;
let blockedIpsList = [];
let failedBlocksMap = {}; // ip -> error string

// DOM Elements
const statTotalPackets = document.getElementById('statTotalPackets');
const statPPS = document.getElementById('statPPS');
const statThreats = document.getElementById('statThreats');
const statCritical = document.getElementById('statCritical');
const statHigh = document.getElementById('statHigh');
const statMed = document.getElementById('statMed');
const statBlocked = document.getElementById('statBlocked');
const statAdminStatus = document.getElementById('statAdminStatus');
const statFlows = document.getElementById('statFlows');
const engineModeText = document.getElementById('engineModeText');
const packetTableBody = document.getElementById('packetTableBody');
const packetTableWrapper = document.getElementById('packetTableWrapper');
const emptyTableNotice = document.getElementById('emptyTableNotice');
const packetBufferCount = document.getElementById('packetBufferCount');
const alertsContainer = document.getElementById('alertsContainer');
const alertsEmptyState = document.getElementById('alertsEmptyState');
const alertCountBadge = document.getElementById('alertCountBadge');
const flowStatsContainer = document.getElementById('flowStatsContainer');
const flowStatsEmpty = document.getElementById('flowStatsEmpty');
const quarantineContainer = document.getElementById('quarantineContainer');
const quarantineEmpty = document.getElementById('quarantineEmpty');
const quarantineCountBadge = document.getElementById('quarantineCountBadge');
const protocolSummaryText = document.getElementById('protocolSummaryText');

const btnToggleSniff = document.getElementById('btnToggleSniff');
const btnToggleSim = document.getElementById('btnToggleSim');
const btnToggleAutoBlock = document.getElementById('btnToggleAutoBlock');
const autoBlockBtnText = document.getElementById('autoBlockBtnText');
const autoBlockIcon = document.getElementById('autoBlockIcon');
const btnToggleSimMode = document.getElementById('btnToggleSimMode');
const simModeBtnText = document.getElementById('simModeBtnText');
const simModeIcon = document.getElementById('simModeIcon');
const btnSyncFirewall = document.getElementById('btnSyncFirewall');
const btnClear = document.getElementById('btnClear');
const btnPauseStream = document.getElementById('btnPauseStream');
const pauseIcon = document.getElementById('pauseIcon');
const chkAutoScroll = document.getElementById('chkAutoScroll');
const searchInput = document.getElementById('searchInput');
const threatFilterSelect = document.getElementById('threatFilterSelect');
const ifaceSelect = document.getElementById('ifaceSelect');

// Inspector Modal Elements
const inspectorModal = document.getElementById('inspectorModal');
const btnCloseModal = document.getElementById('btnCloseModal');
const btnCloseModalBottom = document.getElementById('btnCloseModalBottom');
const modalPacketId = document.getElementById('modalPacketId');
const modalPacketSummary = document.getElementById('modalPacketSummary');
const modalThreatBanner = document.getElementById('modalThreatBanner');
const modalThreatIcon = document.getElementById('modalThreatIcon');
const modalThreatTitle = document.getElementById('modalThreatTitle');
const modalThreatBadge = document.getElementById('modalThreatBadge');
const modalThreatReasons = document.getElementById('modalThreatReasons');
const modalProto = document.getElementById('modalProto');
const modalLength = document.getElementById('modalLength');
const modalFlags = document.getElementById('modalFlags');
const modalTime = document.getElementById('modalTime');
const modalSrc = document.getElementById('modalSrc');
const modalDst = document.getElementById('modalDst');
const modalDnsSection = document.getElementById('modalDnsSection');
const modalDnsQuery = document.getElementById('modalDnsQuery');
const modalDnsLen = document.getElementById('modalDnsLen');
const modalDnsEntropy = document.getElementById('modalDnsEntropy');
const modalPayloadLen = document.getElementById('modalPayloadLen');
const modalAsciiDump = document.getElementById('modalAsciiDump');
const modalHexDump = document.getElementById('modalHexDump');

// Initialize on Load
document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initCharts();
  loadInterfaces();
  loadBlockedList();
  connectWebSocket();
  setupEventListeners();
  requestAnimationFrame(renderLoop);
});

// Setup Charts
function initCharts() {
  // 1. Packets Per Second Live Line Chart
  const ctxPPS = document.getElementById('ppsChart').getContext('2d');
  const gradient = ctxPPS.createLinearGradient(0, 0, 0, 180);
  gradient.addColorStop(0, 'rgba(6, 182, 212, 0.4)');
  gradient.addColorStop(1, 'rgba(6, 182, 212, 0.0)');

  ppsChartInstance = new Chart(ctxPPS, {
    type: 'line',
    data: {
      labels: ppsLabels,
      datasets: [{
        label: 'Packets / sec',
        data: ppsHistory,
        borderColor: '#06b6d4',
        borderWidth: 2,
        backgroundColor: gradient,
        fill: true,
        tension: 0.35,
        pointRadius: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { display: false },
        tooltip: { enabled: true }
      },
      scales: {
        x: {
          display: false,
          grid: { display: false }
        },
        y: {
          beginAtZero: true,
          suggestedMax: 20,
          grid: { color: 'rgba(51, 65, 85, 0.25)' },
          ticks: { color: '#64748b', font: { size: 10 } }
        }
      }
    }
  });

  // 2. Protocol Breakdown Donut Chart
  const ctxProto = document.getElementById('protocolChart').getContext('2d');
  protocolChartInstance = new Chart(ctxProto, {
    type: 'doughnut',
    data: {
      labels: ['TCP', 'UDP', 'DNS', 'TLS/HTTPS', 'HTTP', 'ARP', 'OTHER'],
      datasets: [{
        data: [0, 0, 0, 0, 0, 0, 0],
        backgroundColor: [
          '#38bdf8', // TCP - Sky
          '#a855f7', // UDP - Purple
          '#f59e0b', // DNS - Amber
          '#10b981', // TLS - Emerald
          '#06b6d4', // HTTP - Cyan
          '#f97316', // ARP - Orange
          '#64748b'  // OTHER - Slate
        ],
        borderWidth: 1,
        borderColor: '#0b1120'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            boxWidth: 10,
            padding: 8,
            color: '#94a3b8',
            font: { size: 10 }
          }
        }
      }
    }
  });
}

// Fetch Interfaces
async function loadInterfaces() {
  try {
    const res = await fetch(`${API_BASE}/api/interfaces`);
    const data = await res.json();
    if (data.interfaces && data.interfaces.length > 0) {
      ifaceSelect.innerHTML = '';
      data.interfaces.forEach((iface) => {
        const opt = document.createElement('option');
        opt.value = iface.id;
        opt.textContent = iface.name;
        if (data.active_interface && iface.id === data.active_interface) {
          opt.selected = true;
        }
        ifaceSelect.appendChild(opt);
      });
    }
  } catch (err) {
    console.error('Failed to load interfaces:', err);
  }
}

// WebSocket Connection with Resilient Fallback Polling
function connectWebSocket() {
  const wsUrl = `${WS_BASE}/ws/packets`;

  try {
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      console.log('[C2 Sentinel] WebSocket connected to', wsUrl);
      updateConnStatus(true);
      if (pollIntervalId) {
        clearInterval(pollIntervalId);
        pollIntervalId = null;
      }
    };

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleServerMessage(msg);
      } catch (e) {
        console.error('Error parsing message:', e);
      }
    };

    socket.onclose = () => {
      updateConnStatus(false);
      startFallbackPolling();
      setTimeout(connectWebSocket, 3000);
    };

    socket.onerror = (err) => {
      console.warn('WebSocket connection error:', err);
      updateConnStatus(false);
    };
  } catch (err) {
    console.error('WebSocket creation failed:', err);
    updateConnStatus(false);
    startFallbackPolling();
  }
}

function startFallbackPolling() {
  if (pollIntervalId) return;
  console.log('[C2 Sentinel] Active fallback polling engaged...');
  pollIntervalId = setInterval(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/packets/recent`);
      if (res.ok) {
        const data = await res.json();
        updateStatsUI(data.stats);
        if (data.blocked_ips) {
          blockedIpsList = data.blocked_ips;
          renderQuarantineList(blockedIpsList, data.active_blocked_count);
        } else if (typeof data.active_blocked_count === 'number') {
          updateBlockedCountUI(data.active_blocked_count);
        }
        if (data.packets && data.packets.length > 0) {
          data.packets.forEach((p) => {
            if (!packetHistory.some((existing) => existing.id === p.id)) {
              if (!isPaused) packetQueue.push(p);
              if (['CRITICAL', 'HIGH', 'MEDIUM'].includes(p.threat_level)) {
                addThreatAlert(p);
              }
            }
          });
        }
        if (data.flow_stats) {
          renderFlowStats(data.flow_stats);
        }
        updateConnStatus(true);
      }
    } catch (e) {
      // Backend not yet reached
    }
  }, 1000);
}

function updateConnStatus(connected) {
  const connPing = document.getElementById('connPing');
  const connDot = document.getElementById('connDot');
  const connText = document.getElementById('connText');

  if (connected) {
    connPing.className = 'animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75';
    connDot.className = 'relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500';
    connText.textContent = 'Connected';
    connText.className = 'text-emerald-400 font-semibold';
  } else {
    connPing.className = 'hidden';
    connDot.className = 'relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500';
    connText.textContent = 'Connecting...';
    connText.className = 'text-rose-400';
  }
}

// Quarantine and Blocker Controller
// Toast Notification
function showToast(msg) {
  let toast = document.getElementById('c2Toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'c2Toast';
    toast.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;background:#1e1b4b;border:1px solid #a855f7;color:#f3e8ff;padding:10px 18px;border-radius:10px;font-size:12px;font-weight:700;box-shadow:0 0 25px rgba(168,85,247,0.5);transition:opacity 0.3s ease;display:none;pointer-events:none;';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.display = 'block';
  toast.style.opacity = '1';
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => { toast.style.display = 'none'; }, 300);
  }, 3500);
}

// Quarantine and Blocker Controller
function updateAutoBlockUI(enabled) {
  autoBlockEnabled = !!enabled;
  if (!btnToggleAutoBlock) return;
  if (autoBlockEnabled) {
    btnToggleAutoBlock.className = 'flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all duration-200 bg-purple-950 border border-purple-500 text-purple-200 shadow-[0_0_15px_rgba(168,85,247,0.4)]';
    btnToggleAutoBlock.innerHTML = `<i data-lucide="shield-alert" class="w-4 h-4 text-purple-400"></i><span class="font-bold">AUTO-BLOCK: ACTIVE</span>`;
  } else {
    btnToggleAutoBlock.className = 'flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all duration-200 bg-slate-900 border border-slate-700/80 text-slate-400 hover:text-white';
    btnToggleAutoBlock.innerHTML = `<i data-lucide="shield-check" class="w-4 h-4 text-emerald-400"></i><span>AUTO-BLOCK: OFF</span>`;
  }
  lucide.createIcons({ root: btnToggleAutoBlock });
}

function updateSimModeUI(enabled) {
  isSimulationMode = !!enabled;
  if (!btnToggleSimMode || !simModeBtnText) return;
  if (isSimulationMode) {
    btnToggleSimMode.className = 'flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all duration-200 bg-sky-950/80 border border-sky-500 text-sky-200 shadow-[0_0_15px_rgba(56,189,248,0.3)]';
    simModeBtnText.textContent = 'MODE: SIMULATION';
    if (simModeIcon) simModeIcon.className = 'w-4 h-4 text-sky-400';
  } else {
    btnToggleSimMode.className = 'flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all duration-200 bg-slate-900 border border-slate-700/80 text-slate-300 hover:border-cyan-500';
    simModeBtnText.textContent = 'MODE: REAL FIREWALL';
    if (simModeIcon) simModeIcon.className = 'w-4 h-4 text-cyan-400';
  }
  lucide.createIcons({ root: btnToggleSimMode });
}

async function toggleSimulationMode() {
  try {
    const res = await fetch(`${API_BASE}/api/simulation/toggle`, { method: 'POST' });
    const data = await res.json();
    updateSimModeUI(data.simulation_mode);
    showToast(`⚙️ Mode: ${data.simulation_mode ? 'Simulation Mode Active' : 'Real Windows Firewall Active'}`);
  } catch (err) {
    console.error('Failed to toggle simulation mode:', err);
  }
}

async function loadBlockedList() {
  try {
    const res = await fetch(`${API_BASE}/api/blocked`);
    if (res.ok) {
      const data = await res.json();
      blockedIpsList = data.blocked_ips || data.blocked || [];
      const activeCount = typeof data.active_blocked_count === 'number'
        ? data.active_blocked_count
        : (typeof data.count === 'number' ? data.count : blockedIpsList.length);
      renderQuarantineList(blockedIpsList, activeCount);
      updateBlockedCountUI(activeCount);
      updateAutoBlockUI(data.auto_block);
      updateSimModeUI(data.simulation_mode);
      if (data.failed && Array.isArray(data.failed)) {
        data.failed.forEach(f => {
          if (f.ip && f.error) failedBlocksMap[f.ip] = f.error;
        });
      }
      if (statAdminStatus) {
        statAdminStatus.textContent = data.is_admin ? "Kernel Firewall Active" : "Software / Sim Active";
      }
    }
  } catch (err) {
    console.warn('Could not load blocked list:', err);
  }
}

function updateThreatCardActions(ip, status, errorMsg) {
  document.querySelectorAll(`.threat-card-actions[data-ip="${ip}"]`).forEach(container => {
    if (status === 'ENFORCED') {
      container.innerHTML = `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-enforced inline-flex items-center gap-1"><i data-lucide="shield-ban" class="w-3 h-3"></i>ENFORCED</span>`;
    } else if (status === 'SIMULATED') {
      container.innerHTML = `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-simulated inline-flex items-center gap-1"><i data-lucide="shield" class="w-3 h-3"></i>SIMULATED</span>`;
    } else if (status === 'FAILED') {
      container.innerHTML = `
        <div class="flex items-center gap-1.5">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold badge-failed cursor-help" title="${escapeHtml(errorMsg || 'Action failed')}">BLOCK FAILED</span>
          <button class="btn-retry" data-ip="${escapeHtml(ip)}" title="Retry blocking this IP">Retry</button>
        </div>
      `;
      const retryBtn = container.querySelector('.btn-retry');
      if (retryBtn) {
        retryBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const card = container.closest('.threat-alert-card');
          const reason = card ? card.dataset.reason : 'Manual Block Retry';
          blockIP(ip, reason, retryBtn);
        });
      }
    } else {
      container.innerHTML = `
        <button class="btn-block-threat" data-ip="${escapeHtml(ip)}" title="Block IP via Windows Firewall">
          <i data-lucide="shield-x" class="w-3 h-3"></i>
          <span>BLOCK IP</span>
        </button>
      `;
      const blkBtn = container.querySelector('.btn-block-threat');
      if (blkBtn) {
        blkBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const card = container.closest('.threat-alert-card');
          const reason = card ? card.dataset.reason : 'Manual Dashboard Block';
          blockIP(ip, reason, blkBtn);
        });
      }
    }
    lucide.createIcons({ root: container });
  });
}

async function blockIP(ip, reason, clickedBtn, forceSimulation = false) {
  if (!ip) return;
  if (clickedBtn) {
    clickedBtn.textContent = 'Blocking...';
    clickedBtn.disabled = true;
  }
  try {
    const res = await fetch(`${API_BASE}/api/block`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ip,
        reason: reason || 'Manual Dashboard Block',
        force_simulation: forceSimulation || isSimulationMode
      })
    });
    const data = await res.json();
    if (data.success && data.record) {
      const targetIp = data.record.ip || ip;
      if (failedBlocksMap[targetIp]) delete failedBlocksMap[targetIp];
      if (Array.isArray(data.blocked_ips)) {
        blockedIpsList = data.blocked_ips;
      } else {
        const existingIdx = blockedIpsList.findIndex(b => b.ip === targetIp);
        if (existingIdx >= 0) {
          blockedIpsList[existingIdx] = data.record;
        } else {
          blockedIpsList.push(data.record);
        }
      }
      const activeCount = typeof data.active_blocked_count === 'number'
        ? data.active_blocked_count
        : blockedIpsList.length;
      renderQuarantineList(blockedIpsList, activeCount);
      updateBlockedCountUI(activeCount);
      updateThreatCardActions(targetIp, data.record.status === 'SIMULATED' ? 'SIMULATED' : 'ENFORCED');
      refilterTable();
      showToast(`🛡️ IP ${targetIp} Quarantined! (${data.record.status})`);
    } else {
      const err = data.error || 'Unknown error occurred.';
      failedBlocksMap[ip] = err;
      updateThreatCardActions(ip, 'FAILED', err);
      if (clickedBtn) {
        clickedBtn.disabled = false;
      }
      if (data.requires_elevation || data.code === 'ELEVATION_REQUIRED') {
        showToast(`❌ Non-Admin: Run Python as Admin or switch to Simulation Mode.`);
      } else {
        showToast(`❌ Block Failed: ${err}`);
      }
    }
  } catch (err) {
    console.error('Failed to block IP:', err);
    failedBlocksMap[ip] = String(err);
    updateThreatCardActions(ip, 'FAILED', String(err));
    if (clickedBtn) {
      clickedBtn.disabled = false;
    }
    showToast(`❌ Network error while blocking ${ip}`);
  }
}

async function unblockIP(ip) {
  if (!ip) return;
  try {
    const res = await fetch(`${API_BASE}/api/unblock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.success) {
      if (Array.isArray(data.blocked_ips)) {
        blockedIpsList = data.blocked_ips;
      } else {
        blockedIpsList = blockedIpsList.filter(b => b.ip !== ip);
      }
      if (failedBlocksMap[ip]) delete failedBlocksMap[ip];
      const activeCount = typeof data.active_blocked_count === 'number'
        ? data.active_blocked_count
        : blockedIpsList.length;
      renderQuarantineList(blockedIpsList, activeCount);
      updateBlockedCountUI(activeCount);
      updateThreatCardActions(ip, 'UNBLOCKED');
      refilterTable();
      showToast(`🔓 Restored connection to ${ip}`);
    } else {
      showToast(`❌ Unblock Failed: ${data.error || 'Error'}`);
    }
  } catch (err) {
    console.error('Failed to unblock IP:', err);
    showToast(`❌ Network error while unblocking ${ip}`);
  }
}

function updateBlockedCountUI(count) {
  const num = (typeof count === 'number' && !isNaN(count))
    ? count
    : (Array.isArray(blockedIpsList) ? blockedIpsList.length : 0);
  if (quarantineCountBadge) {
    quarantineCountBadge.textContent = `${num} blocked`;
  }
  if (statBlocked) {
    statBlocked.textContent = String(num);
  }
}

function renderQuarantineList(list, activeCount) {
  if (!quarantineContainer) return;
  const countToDisplay = (typeof activeCount === 'number' && !isNaN(activeCount))
    ? activeCount
    : (Array.isArray(list) ? list.length : 0);
  updateBlockedCountUI(countToDisplay);

  if (!list || list.length === 0) {
    if (quarantineEmpty) quarantineEmpty.style.display = 'block';
    quarantineContainer.innerHTML = '';
    quarantineContainer.appendChild(quarantineEmpty);
    return;
  }

  if (quarantineEmpty) quarantineEmpty.style.display = 'none';
  quarantineContainer.innerHTML = '';

  list.forEach(item => {
    const card = document.createElement('div');
    card.className = 'quarantine-card';
    const isSim = item.status === 'SIMULATED';
    const statusBadge = isSim
      ? `<span class="px-1.5 py-0.5 rounded text-[9px] font-bold badge-simulated">SIM</span>`
      : `<span class="px-1.5 py-0.5 rounded text-[9px] font-bold badge-enforced">ENFORCED</span>`;

    card.innerHTML = `
      <div class="truncate max-w-[130px]">
        <div class="flex items-center gap-1.5">
          <span class="font-bold text-purple-300 truncate" title="${escapeHtml(item.ip)}">${escapeHtml(item.ip)}</span>
          ${statusBadge}
        </div>
        <div class="text-[9px] text-slate-500 truncate" title="${escapeHtml(item.reason)}">${escapeHtml(item.reason)}</div>
      </div>
      <div class="flex items-center gap-1.5">
        <span class="text-[9px] text-slate-400 font-mono">${item.time_str || ''}</span>
        <button class="btn-unblock" data-ip="${escapeHtml(item.ip)}" title="Remove Firewall Block">Unblock</button>
      </div>
    `;

    const unblockBtn = card.querySelector('.btn-unblock');
    unblockBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      unblockIP(item.ip);
    });

    quarantineContainer.appendChild(card);
  });
}

// Handle Incoming Server Messages
function handleServerMessage(msg) {
  if (msg.type === 'init') {
    isSniffing = msg.is_sniffing;
    isSimulating = msg.is_simulating;
    updateSniffButtonUI();
    updateSimButtonUI();
    updateStatsUI(msg.stats);
    
    // Initialize Quarantine, Simulation Mode and Auto-block state
    if (msg.auto_block !== undefined) updateAutoBlockUI(msg.auto_block);
    if (msg.simulation_mode !== undefined) updateSimModeUI(msg.simulation_mode);
    const initialList = msg.blocked_ips || msg.blocked || [];
    blockedIpsList = initialList;
    const initialCount = typeof msg.active_blocked_count === 'number'
      ? msg.active_blocked_count
      : (typeof msg.blocked_count === 'number' ? msg.blocked_count : initialList.length);
    renderQuarantineList(blockedIpsList, initialCount);
    updateBlockedCountUI(initialCount);

    if (msg.failed_blocks && Array.isArray(msg.failed_blocks)) {
      msg.failed_blocks.forEach(f => {
        if (f.ip && f.error) failedBlocksMap[f.ip] = f.error;
      });
    }
    if (statAdminStatus) {
      statAdminStatus.textContent = msg.is_admin ? "Kernel Firewall Active" : "Software / Sim Active";
    }

    if (msg.recent_packets && Array.isArray(msg.recent_packets)) {
      msg.recent_packets.forEach((pkt) => {
        if (!isPaused) packetQueue.push(pkt);
        if (['CRITICAL', 'HIGH', 'MEDIUM'].includes(pkt.threat_level)) {
          addThreatAlert(pkt);
        }
      });
    }
  } else if (msg.type === 'block_event') {
    if (msg.action === 'blocked' && msg.record) {
      if (failedBlocksMap[msg.record.ip]) delete failedBlocksMap[msg.record.ip];
      const existingIdx = blockedIpsList.findIndex(b => b.ip === msg.record.ip);
      if (existingIdx >= 0) {
        blockedIpsList[existingIdx] = msg.record;
      } else {
        blockedIpsList.push(msg.record);
      }
      const activeCount = typeof msg.active_blocked_count === 'number'
        ? msg.active_blocked_count
        : (typeof msg.blocked_count === 'number' ? msg.blocked_count : blockedIpsList.length);
      renderQuarantineList(blockedIpsList, activeCount);
      updateBlockedCountUI(activeCount);
      updateThreatCardActions(msg.record.ip, msg.record.status === 'SIMULATED' ? 'SIMULATED' : 'ENFORCED');
      if (msg.auto_triggered) {
        showToast(`⚡ AUTO-BLOCKED: Malicious IP ${msg.record.ip} quarantined!`);
      }
    } else if (msg.action === 'block_failed') {
      const targetIp = msg.ip || (msg.record && msg.record.ip);
      if (targetIp) {
        failedBlocksMap[targetIp] = msg.error || 'Block failed';
        updateThreatCardActions(targetIp, 'FAILED', msg.error);
        if (msg.auto_triggered) {
          showToast(`⚠️ Auto-block failed for ${targetIp}: ${msg.error}`);
        }
      }
      if (typeof msg.active_blocked_count === 'number') {
        updateBlockedCountUI(msg.active_blocked_count);
      }
    } else if (msg.action === 'unblocked' && msg.ip) {
      blockedIpsList = blockedIpsList.filter(b => b.ip !== msg.ip);
      if (failedBlocksMap[msg.ip]) delete failedBlocksMap[msg.ip];
      const activeCount = typeof msg.active_blocked_count === 'number'
        ? msg.active_blocked_count
        : (typeof msg.blocked_count === 'number' ? msg.blocked_count : blockedIpsList.length);
      renderQuarantineList(blockedIpsList, activeCount);
      updateBlockedCountUI(activeCount);
      updateThreatCardActions(msg.ip, 'UNBLOCKED');
    }
    refilterTable();
  } else if (msg.type === 'autoblock_toggle') {
    updateAutoBlockUI(msg.auto_block);
  } else if (msg.type === 'simulation_toggle') {
    updateSimModeUI(msg.simulation_mode);
    if (msg.blocked_ips) {
      blockedIpsList = msg.blocked_ips;
      renderQuarantineList(blockedIpsList, msg.active_blocked_count);
    } else if (typeof msg.active_blocked_count === 'number') {
      updateBlockedCountUI(msg.active_blocked_count);
    }
  } else if (msg.type === 'firewall_synced') {
    const list = msg.blocked_ips || msg.blocked || [];
    blockedIpsList = list;
    const activeCount = typeof msg.active_blocked_count === 'number'
      ? msg.active_blocked_count
      : (typeof msg.count === 'number' ? msg.count : list.length);
    renderQuarantineList(blockedIpsList, activeCount);
    updateBlockedCountUI(activeCount);
    refilterTable();
  } else if (msg.type === 'packet') {
    if (!isPaused) {
      packetQueue.push(msg.data);
    }
    updateStatsUI(msg.stats);

    // If packet is a significant threat, register an alert card
    if (['CRITICAL', 'HIGH', 'MEDIUM'].includes(msg.data.threat_level)) {
      addThreatAlert(msg.data);
    }
  } else if (msg.type === 'pps_tick') {
    updatePPSChart(msg.pps);
    statPPS.textContent = msg.pps;
    if (msg.flow_stats) {
      renderFlowStats(msg.flow_stats);
    }
  }
}

// UI Stats Update
function updateStatsUI(stats) {
  if (!stats) return;
  statTotalPackets.textContent = stats.total_packets.toLocaleString();
  statThreats.textContent = stats.threats_count.toLocaleString();
  statCritical.textContent = `${stats.critical_count} Crit`;
  statHigh.textContent = `${stats.high_count} High`;
  statMed.textContent = `${stats.medium_count} Med`;
  statFlows.textContent = stats.active_flows || 0;

  // Protocol Doughnut Chart
  if (stats.protocols && protocolChartInstance) {
    const p = stats.protocols;
    protocolChartInstance.data.datasets[0].data = [
      p['TCP'] || 0,
      p['UDP'] || 0,
      p['DNS'] || 0,
      p['TLS/HTTPS'] || 0,
      p['HTTP'] || 0,
      p['ARP'] || 0,
      p['OTHER'] || 0
    ];
    protocolChartInstance.update();
    protocolSummaryText.textContent = `${stats.total_packets} Total`;
  }
}

function updatePPSChart(currentPPS) {
  if (!ppsChartInstance) return;
  ppsHistory.shift();
  ppsHistory.push(currentPPS);
  ppsChartInstance.data.datasets[0].data = ppsHistory;
  ppsChartInstance.update();
}

// Smooth Render Loop using requestAnimationFrame
function renderLoop() {
  if (packetQueue.length > 0) {
    // Process up to 25 packets per animation frame to prevent UI lag
    const batch = packetQueue.splice(0, 25);
    batch.forEach((pkt) => {
      packetHistory.push(pkt);
      if (packetHistory.length > 500) {
        packetHistory.shift();
      }

      if (matchesFilter(pkt)) {
        appendPacketRow(pkt);
      }
    });

    packetBufferCount.textContent = `Buffer: ${packetTableBody.children.length} / ${MAX_TABLE_ROWS}`;

    if (autoScroll && chkAutoScroll.checked) {
      packetTableWrapper.scrollTop = packetTableWrapper.scrollHeight;
    }
  }

  requestAnimationFrame(renderLoop);
}

// Filter Checker
function matchesFilter(pkt) {
  // Protocol Filter
  if (selectedProtocol !== 'ALL') {
    if (selectedProtocol === 'HTTP' && pkt.protocol !== 'HTTP') return false;
    if (selectedProtocol === 'TLS/HTTPS' && pkt.protocol !== 'TLS/HTTPS') return false;
    if (selectedProtocol === 'TCP' && pkt.protocol !== 'TCP') return false;
    if (selectedProtocol === 'UDP' && pkt.protocol !== 'UDP') return false;
    if (selectedProtocol === 'DNS' && pkt.protocol !== 'DNS') return false;
    if (selectedProtocol === 'ARP' && pkt.protocol !== 'ARP') return false;
  }

  // Threat Filter
  if (selectedThreatFilter === 'THREATS') {
    if (!['CRITICAL', 'HIGH', 'MEDIUM'].includes(pkt.threat_level)) return false;
  } else if (selectedThreatFilter === 'CRITICAL') {
    if (pkt.threat_level !== 'CRITICAL') return false;
  } else if (selectedThreatFilter === 'BLOCKED') {
    const isBlk = pkt.is_blocked || (blockedIpsList && blockedIpsList.some(b => b.ip === pkt.dst_ip || b.ip === pkt.src_ip));
    if (!isBlk) return false;
  }

  // Search Filter
  if (searchQuery.trim() !== '') {
    const q = searchQuery.toLowerCase();
    const match =
      (pkt.src_ip && pkt.src_ip.toLowerCase().includes(q)) ||
      (pkt.dst_ip && pkt.dst_ip.toLowerCase().includes(q)) ||
      (pkt.protocol && pkt.protocol.toLowerCase().includes(q)) ||
      (pkt.dns_query && pkt.dns_query.toLowerCase().includes(q)) ||
      (pkt.payload_preview && pkt.payload_preview.toLowerCase().includes(q)) ||
      String(pkt.src_port).includes(q) ||
      String(pkt.dst_port).includes(q);
    if (!match) return false;
  }

  return true;
}

// Append Row to Table
function appendPacketRow(pkt) {
  if (emptyTableNotice) {
    emptyTableNotice.style.display = 'none';
  }

  // Maintain max rows limit
  while (packetTableBody.children.length >= MAX_TABLE_ROWS) {
    packetTableBody.removeChild(packetTableBody.firstChild);
  }

  const isBlocked = pkt.is_blocked || (blockedIpsList && blockedIpsList.some(b => b.ip === pkt.dst_ip || b.ip === pkt.src_ip));

  const tr = document.createElement('tr');
  tr.className = `packet-row text-xs ${getThreatRowClass(pkt.threat_level)} ${isBlocked ? 'is-blocked' : ''}`;
  tr.dataset.packetId = pkt.id;

  // Protocol badge color
  let protoColor = 'text-cyan-400 bg-cyan-950/60 border-cyan-800';
  if (pkt.protocol === 'DNS' || pkt.protocol === 'mDNS') protoColor = 'text-amber-400 bg-amber-950/60 border-amber-800';
  else if (pkt.protocol === 'TLS/HTTPS') protoColor = 'text-emerald-400 bg-emerald-950/60 border-emerald-800';
  else if (pkt.protocol === 'HTTP') protoColor = 'text-sky-400 bg-sky-950/60 border-sky-800';
  else if (pkt.protocol === 'UDP') protoColor = 'text-purple-400 bg-purple-950/60 border-purple-800';
  else if (pkt.protocol === 'ARP') protoColor = 'text-orange-400 bg-orange-950/60 border-orange-800';
  else if (pkt.protocol === 'IPv6') protoColor = 'text-indigo-400 bg-indigo-950/60 border-indigo-800';

  // Info Column Summary
  let infoSummary = pkt.payload_preview || 'No application payload';
  if (pkt.dns_query) {
    infoSummary = `DNS Query: ${pkt.dns_query}`;
  }

  tr.innerHTML = `
    <td class="py-2.5 px-3 text-slate-500 font-mono">#${pkt.id}</td>
    <td class="py-2.5 px-3 text-slate-400 whitespace-nowrap">${pkt.time_str}</td>
    <td class="py-2.5 px-3">
      <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${protoColor}">${pkt.protocol}</span>
    </td>
    <td class="py-2.5 px-3 text-emerald-400 font-medium whitespace-nowrap">${pkt.src_ip}:${pkt.src_port}</td>
    <td class="py-2.5 px-3 text-rose-400 font-medium whitespace-nowrap">${pkt.dst_ip}:${pkt.dst_port}</td>
    <td class="py-2.5 px-3 text-slate-400">${pkt.length}B</td>
    <td class="py-2.5 px-3 text-slate-300 max-w-[280px] truncate" title="${escapeHtml(infoSummary)}">
      ${escapeHtml(infoSummary)}
    </td>
    <td class="py-2.5 px-3 whitespace-nowrap">
      ${isBlocked ? '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold badge-blocked mr-1">BLOCKED</span>' : ''}
      ${getThreatBadgeHtml(pkt.threat_level, pkt.threat_score)}
    </td>
    <td class="py-2.5 px-3 text-center whitespace-nowrap">
      <button class="inspect-btn p-1.5 rounded bg-slate-800 hover:bg-cyan-900/60 border border-slate-700 hover:border-cyan-500 text-slate-300 hover:text-cyan-300 transition" title="Inspect Packet">
        <i data-lucide="eye" class="w-3.5 h-3.5"></i>
      </button>
    </td>
  `;

  // Row click or Inspect button click
  const inspectBtn = tr.querySelector('.inspect-btn');
  inspectBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    openInspector(pkt);
  });
  tr.addEventListener('click', () => {
    openInspector(pkt);
  });

  packetTableBody.appendChild(tr);
  lucide.createIcons({ root: tr });
}

function getThreatRowClass(level) {
  if (level === 'CRITICAL') return 'threat-critical';
  if (level === 'HIGH') return 'threat-high';
  if (level === 'MEDIUM') return 'threat-medium';
  return '';
}

function getThreatBadgeHtml(level, score) {
  if (level === 'CRITICAL') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-critical flex items-center gap-1 w-fit">
      <span class="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse"></span>CRITICAL (${score})
    </span>`;
  }
  if (level === 'HIGH') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-high flex items-center gap-1 w-fit">
      <span class="w-1.5 h-1.5 rounded-full bg-amber-500"></span>HIGH (${score})
    </span>`;
  }
  if (level === 'MEDIUM') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-medium w-fit">MEDIUM (${score})</span>`;
  }
  if (level === 'LOW') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-low w-fit">LOW (${score})</span>`;
  }
  return `<span class="px-2 py-0.5 rounded text-[10px] font-semibold badge-info w-fit">BENIGN</span>`;
}

// Add Threat Alert Card
function addThreatAlert(pkt) {
  if (alertsEmptyState) {
    alertsEmptyState.style.display = 'none';
  }

  alertsCount++;
  alertCountBadge.textContent = `${alertsCount} alerts`;

  const card = document.createElement('div');
  const isCrit = pkt.threat_level === 'CRITICAL';
  const isHigh = pkt.threat_level === 'HIGH';

  card.className = `threat-alert-card p-3 rounded-xl border text-xs transition duration-200 cursor-pointer ${
    isCrit
      ? 'bg-rose-950/20 border-rose-500/40 hover:border-rose-400'
      : isHigh
      ? 'bg-amber-950/20 border-amber-500/40 hover:border-amber-400'
      : 'bg-yellow-950/20 border-yellow-500/40 hover:border-yellow-400'
  }`;

  const reasonList = (pkt.threat_reasons || [])
    .map((r) => `<li class="text-slate-300 font-sans">${escapeHtml(r)}</li>`)
    .join('');

  const firstReason = (pkt.threat_reasons && pkt.threat_reasons[0]) || 'Malicious C2 Threat';
  card.dataset.reason = firstReason;
  card.dataset.targetIp = pkt.dst_ip;

  const blockedItem = blockedIpsList && blockedIpsList.find(b => b.ip === pkt.dst_ip);
  const isFailed = failedBlocksMap[pkt.dst_ip];

  let actionHtml = '';
  if (blockedItem) {
    if (blockedItem.status === 'SIMULATED') {
      actionHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-simulated inline-flex items-center gap-1"><i data-lucide="shield" class="w-3 h-3"></i>SIMULATED</span>`;
    } else {
      actionHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-enforced inline-flex items-center gap-1"><i data-lucide="shield-ban" class="w-3 h-3"></i>ENFORCED</span>`;
    }
  } else if (isFailed) {
    actionHtml = `<div class="flex items-center gap-1.5"><span class="px-2 py-0.5 rounded text-[10px] font-bold badge-failed cursor-help" title="${escapeHtml(isFailed)}">BLOCK FAILED</span><button class="btn-retry" data-ip="${escapeHtml(pkt.dst_ip)}" title="Retry blocking this IP">Retry</button></div>`;
  } else {
    actionHtml = `<button class="btn-block-threat" data-ip="${escapeHtml(pkt.dst_ip)}" title="Block IP via Windows Firewall"><i data-lucide="shield-x" class="w-3 h-3"></i><span>BLOCK IP</span></button>`;
  }

  card.innerHTML = `
    <div class="flex items-start justify-between gap-2">
      <div class="flex items-center gap-2">
        <i data-lucide="${isCrit ? 'flame' : 'alert-triangle'}" class="w-4 h-4 ${isCrit ? 'text-rose-500' : 'text-amber-500'}"></i>
        <span class="font-bold text-white font-mono">${pkt.src_ip} ➔ ${pkt.dst_ip}:${pkt.dst_port}</span>
      </div>
      <div class="flex items-center gap-2">
        <span class="text-[10px] text-slate-500 font-mono">${pkt.time_str}</span>
        ${getThreatBadgeHtml(pkt.threat_level, pkt.threat_score)}
      </div>
    </div>
    <ul class="mt-2 space-y-1 list-disc list-inside text-[11px] pl-1">
      ${reasonList}
    </ul>
    <div class="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between">
      <span class="text-[10px] text-slate-500 font-mono">Target: ${pkt.dst_ip}</span>
      <div class="flex items-center gap-2">
        <button class="btn-inspect-alert px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-semibold" title="Inspect Deep Packet Details">Details</button>
        <div class="threat-card-actions" data-ip="${escapeHtml(pkt.dst_ip)}">
          ${actionHtml}
        </div>
      </div>
    </div>
  `;

  // Block button handler
  const blockBtn = card.querySelector('.btn-block-threat');
  if (blockBtn) {
    blockBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      blockIP(pkt.dst_ip, firstReason, blockBtn);
    });
  }

  // Retry button handler
  const retryBtn = card.querySelector('.btn-retry');
  if (retryBtn) {
    retryBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      blockIP(pkt.dst_ip, firstReason, retryBtn);
    });
  }

  // Inspect Details button handler
  const inspectBtn = card.querySelector('.btn-inspect-alert');
  if (inspectBtn) {
    inspectBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      openInspector(pkt);
    });
  }

  card.addEventListener('click', () => openInspector(pkt));

  // Prepend new alert to top
  alertsContainer.insertBefore(card, alertsContainer.firstChild);
  lucide.createIcons({ root: card });

  // Limit alerts in DOM
  if (alertsContainer.children.length > 20) {
    alertsContainer.removeChild(alertsContainer.lastChild);
  }
}

// Render Flow Jitter Statistics
function renderFlowStats(flowList) {
  if (!flowList || flowList.length === 0) return;
  if (flowStatsEmpty) flowStatsEmpty.style.display = 'none';

  flowStatsContainer.innerHTML = '';
  flowList.forEach((f) => {
    const item = document.createElement('div');
    const isSuspicious = f.jitter < 0.20 && f.count >= 5;
    item.className = `p-2.5 rounded-lg border flex items-center justify-between text-xs font-mono ${
      isSuspicious
        ? 'bg-rose-950/30 border-rose-500/50 text-rose-300'
        : 'bg-slate-900 border-slate-800 text-slate-300'
    }`;

    item.innerHTML = `
      <div class="truncate max-w-[200px]" title="${escapeHtml(f.flow)}">
        <div class="font-semibold text-white truncate">${escapeHtml(f.flow)}</div>
        <div class="text-[10px] text-slate-400">Hits: ${f.count} packets</div>
      </div>
      <div class="text-right">
        <div class="font-bold ${isSuspicious ? 'text-rose-400' : 'text-cyan-400'}">
          Interval: ~${f.mean_interval}s
        </div>
        <div class="text-[10px] ${isSuspicious ? 'text-rose-300 font-bold' : 'text-slate-500'}">
          Jitter: ${(f.jitter * 100).toFixed(1)}% ${isSuspicious ? '⚠️ BEACON' : ''}
        </div>
      </div>
    `;
    flowStatsContainer.appendChild(item);
  });
}

// Deep Packet Inspector Modal
function openInspector(pkt) {
  modalPacketId.textContent = `#${pkt.id}`;
  modalPacketSummary.textContent = `${pkt.protocol} Flow: ${pkt.src_ip}:${pkt.src_port} -> ${pkt.dst_ip}:${pkt.dst_port}`;

  // Threat Banner
  const isCrit = pkt.threat_level === 'CRITICAL';
  const isHigh = pkt.threat_level === 'HIGH';
  const isMed = pkt.threat_level === 'MEDIUM';

  if (isCrit || isHigh || isMed) {
    modalThreatBanner.className = `p-4 rounded-xl border flex items-start gap-4 ${
      isCrit ? 'bg-rose-950/40 border-rose-500 text-rose-200' : 'bg-amber-950/40 border-amber-500 text-amber-200'
    }`;
    modalThreatIcon.innerHTML = `<i data-lucide="shield-alert" class="w-6 h-6 ${isCrit ? 'text-rose-400' : 'text-amber-400'}"></i>`;
    modalThreatTitle.textContent = `Threat Score: ${pkt.threat_score} / 100 (${pkt.threat_level} SEVERITY)`;
    modalThreatBadge.className = isCrit ? 'px-2.5 py-0.5 rounded font-bold badge-critical' : 'px-2.5 py-0.5 rounded font-bold badge-high';
    modalThreatBadge.textContent = pkt.threat_level;

    modalThreatReasons.innerHTML = (pkt.threat_reasons || [])
      .map((r) => `<li class="font-sans">${escapeHtml(r)}</li>`)
      .join('');
  } else {
    modalThreatBanner.className = 'p-4 rounded-xl border bg-emerald-950/20 border-emerald-800/40 text-emerald-200 flex items-start gap-4';
    modalThreatIcon.innerHTML = `<i data-lucide="shield-check" class="w-6 h-6 text-emerald-400"></i>`;
    modalThreatTitle.textContent = 'Threat Score: 0 / 100 (BENIGN)';
    modalThreatBadge.className = 'px-2.5 py-0.5 rounded font-bold badge-info';
    modalThreatBadge.textContent = 'BENIGN';
    modalThreatReasons.innerHTML = '<li class="font-sans">Traffic patterns appear standard; no known C2 signatures or periodic beacons triggered.</li>';
  }

  // Headers
  modalProto.textContent = pkt.protocol;
  modalLength.textContent = `${pkt.length} bytes`;
  modalFlags.textContent = pkt.flags || 'None';
  modalTime.textContent = pkt.time_str;
  modalSrc.textContent = `${pkt.src_ip}:${pkt.src_port}`;
  modalDst.textContent = `${pkt.dst_ip}:${pkt.dst_port}`;

  // DNS Section
  if (pkt.dns_query) {
    modalDnsSection.classList.remove('hidden');
    modalDnsQuery.textContent = pkt.dns_query;
    modalDnsLen.textContent = pkt.dns_query.length;
    modalDnsEntropy.textContent = pkt.dns_entropy !== undefined ? pkt.dns_entropy : 'N/A';
  } else {
    modalDnsSection.classList.add('hidden');
  }

  // Payloads
  modalPayloadLen.textContent = `${pkt.payload_len || 0} bytes`;
  modalAsciiDump.textContent = pkt.payload_preview || 'No payload bytes available for this layer.';
  modalHexDump.textContent = pkt.hex_preview || '00 00 00 00';

  inspectorModal.classList.remove('hidden');
  lucide.createIcons({ root: inspectorModal });
}

function closeInspector() {
  inspectorModal.classList.add('hidden');
}

// UI Controls & Handlers
function setupEventListeners() {
  // Toggle Sniffer Button
  btnToggleSniff.addEventListener('click', async () => {
    if (!isSniffing) {
      const iface = ifaceSelect.value;
      try {
        const res = await fetch(`${API_BASE}/api/capture/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ interface: iface })
        });
        const data = await res.json();
        if (data.status === 'started') {
          isSniffing = true;
          updateSniffButtonUI();
        }
      } catch (err) {
        alert('Failed to start sniffer: ' + err.message);
      }
    } else {
      try {
        const res = await fetch(`${API_BASE}/api/capture/stop`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'stopped') {
          isSniffing = false;
          updateSniffButtonUI();
        }
      } catch (err) {
        alert('Failed to stop sniffer: ' + err.message);
      }
    }
  });

  // Switch Interface Dropdown
  ifaceSelect.addEventListener('change', async () => {
    const selectedIface = ifaceSelect.value;
    try {
      const res = await fetch(`${API_BASE}/api/capture/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedIface })
      });
      const data = await res.json();
      if (data.status === 'started') {
        isSniffing = true;
        updateSniffButtonUI();
      }
    } catch (err) {
      console.error('Failed to switch interface:', err);
    }
  });

  // Toggle C2 Simulator
  btnToggleSim.addEventListener('click', async () => {
    try {
      const res = await fetch(`${API_BASE}/api/simulator/toggle`, { method: 'POST' });
      const data = await res.json();
      isSimulating = data.is_simulating;
      updateSimButtonUI();
    } catch (err) {
      alert('Failed to toggle simulator: ' + err.message);
    }
  });

  // Toggle Auto-Block
  if (btnToggleAutoBlock) {
    btnToggleAutoBlock.addEventListener('click', async () => {
      try {
        const res = await fetch(`${API_BASE}/api/autoblock/toggle`, { method: 'POST' });
        const data = await res.json();
        updateAutoBlockUI(data.auto_block);
        showToast(data.auto_block ? '🛡️ Auto-Block ACTIVE: Critical threats will be blocked automatically!' : '⚠️ Auto-Block DISABLED.');
      } catch (err) {
        showToast('Failed to toggle auto-block: ' + err.message);
      }
    });
  }

  // Toggle Simulation Mode Button
  if (btnToggleSimMode) {
    btnToggleSimMode.addEventListener('click', toggleSimulationMode);
  }

  // Firewall Sync Button
  if (btnSyncFirewall) {
    btnSyncFirewall.addEventListener('click', async () => {
      const icon = btnSyncFirewall.querySelector('i');
      if (icon) icon.classList.add('animate-spin');
      try {
        const res = await fetch(`${API_BASE}/api/firewall/sync`, { method: 'POST' });
        const data = await res.json();
        await loadBlockedList();
        showToast(`🔄 Windows Firewall synchronized (${data.synced_count || 0} active rules)`);
      } catch (e) {
        showToast(`⚠️ Sync failed: ${e.message}`);
      } finally {
        if (icon) icon.classList.remove('animate-spin');
      }
    });
  }

  // Clear Button
  btnClear.addEventListener('click', async () => {
    if (confirm('Clear all packet logs and threat history?')) {
      try {
        await fetch(`${API_BASE}/api/clear`, { method: 'POST' });
        packetTableBody.innerHTML = '';
        if (emptyTableNotice) emptyTableNotice.style.display = '';
        packetTableBody.appendChild(emptyTableNotice);
        alertsContainer.innerHTML = '';
        if (alertsEmptyState) alertsEmptyState.style.display = '';
        alertsContainer.appendChild(alertsEmptyState);
        alertsCount = 0;
        alertCountBadge.textContent = '0 alerts';
        flowStatsContainer.innerHTML = '';
        if (flowStatsEmpty) flowStatsEmpty.style.display = '';
        flowStatsContainer.appendChild(flowStatsEmpty);
        packetHistory = [];
        packetQueue = [];
      } catch (err) {
        console.error(err);
      }
    }
  });

  // Pause Button
  btnPauseStream.addEventListener('click', () => {
    isPaused = !isPaused;
    btnPauseStream.className = isPaused
      ? 'p-1.5 rounded-lg bg-amber-600 text-white transition'
      : 'p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition';
    pauseIcon.setAttribute('data-lucide', isPaused ? 'play' : 'pause');
    lucide.createIcons({ root: btnPauseStream });
  });

  // Protocol Filter Buttons
  document.querySelectorAll('.proto-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.proto-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      selectedProtocol = btn.dataset.proto;
      refilterTable();
    });
  });

  // Threat Filter Select
  threatFilterSelect.addEventListener('change', () => {
    selectedThreatFilter = threatFilterSelect.value;
    refilterTable();
  });

  // Search Input
  let searchTimeout = null;
  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      searchQuery = searchInput.value;
      refilterTable();
    }, 200);
  });

  // Modal Closers
  btnCloseModal.addEventListener('click', closeInspector);
  btnCloseModalBottom.addEventListener('click', closeInspector);
  inspectorModal.addEventListener('click', (e) => {
    if (e.target === inspectorModal) closeInspector();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeInspector();
  });
}

function updateSniffButtonUI() {
  if (isSniffing) {
    btnToggleSniff.className = 'flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all duration-200 bg-rose-600 hover:bg-rose-500 text-white shadow-[0_0_15px_rgba(244,63,94,0.4)]';
    btnToggleSniff.innerHTML = `<i data-lucide="square" class="w-4 h-4"></i><span>STOP SNIFFER</span>`;
    engineModeText.textContent = 'SNIFFING LIVE';
  } else {
    btnToggleSniff.className = 'flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all duration-200 bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.3)]';
    btnToggleSniff.innerHTML = `<i data-lucide="play" class="w-4 h-4"></i><span>START SNIFFER</span>`;
    engineModeText.textContent = isSimulating ? 'SIMULATION' : 'IDLE / READY';
  }
  lucide.createIcons({ root: btnToggleSniff });
}

function updateSimButtonUI() {
  if (isSimulating) {
    btnToggleSim.classList.add('sim-active');
    btnToggleSim.innerHTML = `<i data-lucide="cpu" class="w-4 h-4 animate-spin"></i><span>STOP SIMULATION</span>`;
    engineModeText.textContent = 'SIMULATION';
  } else {
    btnToggleSim.classList.remove('sim-active');
    btnToggleSim.innerHTML = `<i data-lucide="cpu" class="w-4 h-4"></i><span>SIMULATE C2 ATTACK</span>`;
    engineModeText.textContent = isSniffing ? 'SNIFFING LIVE' : 'IDLE / READY';
  }
  lucide.createIcons({ root: btnToggleSim });
}

function refilterTable() {
  packetTableBody.innerHTML = '';
  const filtered = packetHistory.filter(matchesFilter).slice(-MAX_TABLE_ROWS);
  if (filtered.length === 0) {
    if (emptyTableNotice) {
      emptyTableNotice.style.display = '';
      packetTableBody.appendChild(emptyTableNotice);
    }
  } else {
    filtered.forEach(appendPacketRow);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
