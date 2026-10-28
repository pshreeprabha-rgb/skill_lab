#!/usr/bin/env python3
"""
serve_dashboard.py — Lightweight HTTP Server for Threat Hunting Dashboard
Serves the skill_lab workspace to permit browser fetch() requests to load
outputs/processed_data.json without CORS / local-file restrictions.

Usage:
    python scripts/serve_dashboard.py [--port 8080] [--no-browser]
"""

import os
import sys
import argparse
import webbrowser
from pathlib import Path
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

ROOT = Path(__file__).resolve().parent.parent

class CustomHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        # Enable CORS headers so fetch() always works
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

def main():
    parser = argparse.ArgumentParser(description="Serve Threat Hunting Dashboard locally")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()

    port = args.port
    server = None

    for attempt in range(5):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), CustomHandler)
            break
        except OSError:
            print(f"[-] Port {port} is in use, trying {port + 1}...")
            port += 1

    if server is None:
        print("[-] Could not bind to any port.", file=sys.stderr)
        sys.exit(1)

    url = f"http://localhost:{port}/src/summary.html"
    print("\n" + "="*70)
    print(" WINDOWS THREAT HUNTING DASHBOARD SERVER")
    print("="*70)
    print(f"[+] Root directory:  {ROOT}")
    print(f"[+] Serving at:      {url}")
    print("[+] Press Ctrl+C to stop the server.")
    print("="*70 + "\n")

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        server.server_close()

if __name__ == "__main__":
    main()
