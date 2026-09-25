import os
import sys
import webbrowser
import threading
import time

def check_dependencies():
    missing = []
    for pkg in ["fastapi", "uvicorn", "scapy"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    
    if missing:
        print(f"[!] Missing required Python packages: {', '.join(missing)}")
        print("[!] Install them using: pip install " + " ".join(missing))
        sys.exit(1)

def open_browser():
    time.sleep(1.2)
    print("[*] Opening C2 Sentinel Dashboard in your browser: http://localhost:8000")
    webbrowser.open("http://localhost:8000")

def main():
    print("=" * 65)
    print("      C2 SENTINEL // Real-Time C2 Detection & Packet Sniffer   ")
    print("=" * 65)
    check_dependencies()

    backend_dir = os.path.join(os.path.dirname(__file__), "backend")
    sys.path.insert(0, backend_dir)

    import uvicorn
    from app import app

    # Launch browser automatically
    threading.Thread(target=open_browser, daemon=True).start()

    print("[*] Starting backend server on http://localhost:8000")
    print("[*] Accessible locally at http://localhost:8000 and across your local network.")
    print("[*] Press Ctrl+C to terminate.")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

if __name__ == "__main__":
    main()
