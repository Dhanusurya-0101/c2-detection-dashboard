import asyncio
import os
from collections import deque
from typing import Set, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from detector import C2Detector
from sniffer import PacketSniffer
from simulator import TrafficSimulator
from blocker import C2Blocker

app = FastAPI(title="C2 Detection & Live Packet Sniffer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Path to frontend
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

# Initialize Core Services
detector = C2Detector()
blocker = C2Blocker()
active_connections: Set[WebSocket] = set()
recent_packets = deque(maxlen=60)
loop: asyncio.AbstractEventLoop = None

# Stats tracking
stats = {
    "total_packets": 0,
    "threats_count": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "protocols": {"TCP": 0, "UDP": 0, "DNS": 0, "TLS/HTTPS": 0, "HTTP": 0, "ARP": 0, "OTHER": 0},
    "recent_pps": 0,
    "pps_counter": 0,
    "active_flows": 0
}

def broadcast_packet_sync(packet_data: dict):
    """Callback invoked from sniffer / simulator background threads."""
    global stats
    stats["total_packets"] += 1
    stats["pps_counter"] += 1

    dst_ip = packet_data.get("dst_ip", "")
    src_ip = packet_data.get("src_ip", "")
    
    # Check if either endpoint is currently blocked
    is_blocked = blocker.is_blocked(dst_ip) or blocker.is_blocked(src_ip)
    packet_data["is_blocked"] = is_blocked

    # Update protocol distribution
    proto = packet_data.get("protocol", "OTHER")
    if proto in stats["protocols"]:
        stats["protocols"][proto] += 1
    else:
        stats["protocols"]["OTHER"] += 1

    # Threat metrics & Active Auto-Block Remediation
    sev = packet_data.get("threat_level", "INFO")
    if sev in ("CRITICAL", "HIGH", "MEDIUM"):
        stats["threats_count"] += 1
        if sev == "CRITICAL":
            stats["critical_count"] += 1
        elif sev == "HIGH":
            stats["high_count"] += 1
        elif sev == "MEDIUM":
            stats["medium_count"] += 1

        # Real-time Auto-Block for actionable C2 threats without waiting for manual action
        if blocker.auto_block_enabled and sev in ("CRITICAL", "HIGH"):
            target_ip = dst_ip if blocker.is_safe_ip(dst_ip) else (src_ip if blocker.is_safe_ip(src_ip) else None)
            if target_ip and not blocker.is_blocked(target_ip):
                first_reason = packet_data.get("threat_reasons", [f"Automated {sev} C2 Threat"])[0]
                block_res = blocker.block_ip(
                    target_ip,
                    reason=f"Auto-Block ({sev}): {first_reason}",
                    trigger_type="AUTO"
                )
                packet_data["is_blocked"] = True
                is_blocked = True
                if active_connections and loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        _broadcast_message({
                            "type": "block_event",
                            "action": "blocked",
                            "record": block_res.get("record"),
                            "blocked_count": len(blocker.blocked_ips),
                            "auto_triggered": True
                        }), loop
                    )

    stats["active_flows"] = len(detector.flows)
    recent_packets.append(packet_data)

    # Broadcast to connected WebSocket clients via event loop
    if active_connections and loop and loop.is_running():
        msg = {
            "type": "packet",
            "data": packet_data,
            "stats": {
                "total_packets": stats["total_packets"],
                "threats_count": stats["threats_count"],
                "critical_count": stats["critical_count"],
                "high_count": stats["high_count"],
                "medium_count": stats["medium_count"],
                "protocols": stats["protocols"],
                "recent_pps": stats["recent_pps"],
                "active_flows": stats["active_flows"],
                "blocked_count": len(blocker.blocked_ips)
            }
        }
        asyncio.run_coroutine_threadsafe(_broadcast_message(msg), loop)

async def _broadcast_message(msg: dict):
    disconnected = set()
    for ws in list(active_connections):
        try:
            await asyncio.wait_for(ws.send_json(msg), timeout=1.5)
        except Exception:
            disconnected.add(ws)
    for ws in disconnected:
        active_connections.discard(ws)

sniffer = PacketSniffer(packet_callback=broadcast_packet_sync, detector=detector)
simulator = TrafficSimulator(packet_callback=broadcast_packet_sync, detector=detector)

async def pps_monitor_task():
    """Background task to calculate Packets Per Second every 1 second."""
    global stats
    while True:
        await asyncio.sleep(1.0)
        stats["recent_pps"] = stats["pps_counter"]
        stats["pps_counter"] = 0
        if active_connections:
            tick_msg = {
                "type": "pps_tick",
                "pps": stats["recent_pps"],
                "total_packets": stats["total_packets"],
                "threats_count": stats["threats_count"],
                "flow_stats": detector.get_flow_stats()
            }
            await _broadcast_message(tick_msg)

@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_running_loop()
    asyncio.create_task(pps_monitor_task())
    
    # Automatically start live sniffing on the active Internet/Wi-Fi adapter
    try:
        best_iface = sniffer.get_default_interface()
        sniffer.start(interface=best_iface)
        print(f"[*] Auto-started live capture on active interface: {best_iface}")
    except Exception as e:
        print(f"[!] Notice: Live capture auto-start: {e}")

@app.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    try:
        # Send initial state with recent packets and blocked registry
        await websocket.send_json({
            "type": "init",
            "is_sniffing": sniffer.is_running,
            "is_simulating": simulator.is_running,
            "current_interface": sniffer.current_interface,
            "stats": stats,
            "recent_packets": list(recent_packets),
            "blocked_ips": blocker.get_blocked_list(),
            "auto_block": blocker.auto_block_enabled,
            "is_admin": blocker.is_admin
        })
        while True:
            # Keep receiving client commands or heartbeat pings
            data = await websocket.receive_text()
            if "ping" in data:
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        active_connections.discard(websocket)
    except Exception:
        active_connections.discard(websocket)

@app.get("/api/packets/recent")
def get_recent_packets():
    return {
        "packets": list(recent_packets),
        "stats": stats,
        "is_sniffing": sniffer.is_running,
        "is_simulating": simulator.is_running,
        "active_interface": sniffer.current_interface,
        "flow_stats": detector.get_flow_stats(),
        "blocked_ips": blocker.get_blocked_list(),
        "auto_block": blocker.auto_block_enabled
    }

class BlockRequest(BaseModel):
    ip: str
    reason: str = "Manual Block"

class UnblockRequest(BaseModel):
    ip: str

@app.get("/api/blocked")
def get_blocked():
    return {
        "blocked": blocker.get_blocked_list(),
        "count": len(blocker.blocked_ips),
        "auto_block": blocker.auto_block_enabled,
        "is_admin": blocker.is_admin
    }

@app.post("/api/block")
async def block_ip_endpoint(req: BlockRequest):
    res = blocker.block_ip(req.ip, reason=req.reason, trigger_type="MANUAL")
    if res.get("success"):
        await _broadcast_message({
            "type": "block_event",
            "action": "blocked",
            "record": res.get("record"),
            "blocked_count": len(blocker.blocked_ips)
        })
    return res

@app.post("/api/unblock")
async def unblock_ip_endpoint(req: UnblockRequest):
    res = blocker.unblock_ip(req.ip)
    if res.get("success"):
        await _broadcast_message({
            "type": "block_event",
            "action": "unblocked",
            "ip": req.ip,
            "blocked_count": len(blocker.blocked_ips)
        })
    return res

@app.post("/api/autoblock/toggle")
async def toggle_autoblock_endpoint():
    is_enabled = blocker.toggle_auto_block()
    await _broadcast_message({
        "type": "autoblock_toggle",
        "auto_block": is_enabled
    })
    return {"auto_block": is_enabled}

@app.get("/api/interfaces")
def get_interfaces():
    return {
        "interfaces": sniffer.get_interfaces(),
        "active_interface": sniffer.current_interface
    }

class StartCaptureRequest(BaseModel):
    interface: str = "default"

@app.post("/api/capture/start")
def start_capture(req: StartCaptureRequest):
    sniffer.start(interface=req.interface)
    return {"status": "started", "interface": req.interface}

@app.post("/api/capture/stop")
def stop_capture():
    sniffer.stop()
    return {"status": "stopped"}

@app.post("/api/simulator/toggle")
def toggle_simulator():
    if simulator.is_running:
        simulator.stop()
        return {"status": "stopped", "is_simulating": False}
    else:
        simulator.start()
        return {"status": "started", "is_simulating": True}

@app.post("/api/clear")
def clear_data():
    global stats
    stats["total_packets"] = 0
    stats["threats_count"] = 0
    stats["critical_count"] = 0
    stats["high_count"] = 0
    stats["medium_count"] = 0
    stats["protocols"] = {"TCP": 0, "UDP": 0, "DNS": 0, "TLS/HTTPS": 0, "HTTP": 0, "ARP": 0, "OTHER": 0}
    stats["pps_counter"] = 0
    stats["recent_pps"] = 0
    detector.flows.clear()
    detector.flow_stats.clear()
    return {"status": "cleared"}

@app.get("/api/stats")
def get_stats():
    return {
        "stats": stats,
        "is_sniffing": sniffer.is_running,
        "is_simulating": simulator.is_running,
        "active_interface": sniffer.current_interface,
        "flow_stats": detector.get_flow_stats()
    }

# Mount static frontend directory
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>C2 Detection Dashboard: Frontend files not found</h1>")

@app.get("/style.css")
def serve_css():
    return FileResponse(os.path.join(FRONTEND_DIR, "style.css"))

@app.get("/app.js")
def serve_js():
    return FileResponse(os.path.join(FRONTEND_DIR, "app.js"))

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
