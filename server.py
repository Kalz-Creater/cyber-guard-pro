"""
SentinelOps - Local Security Server Runner
Launches a local HTTP server with automatic browser opening.
"""
import http.server
import socketserver
import webbrowser
import os
import sys

PORT = 8080

class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Enable CORS and caching headers for local development
        self.send_header('Cache-Control', 'no-store, must-revalidate')
        super().end_headers()

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print(f"============================================================")
    print(f"  SENTINEL OPS // Cyber Threat Intelligence & DevSecOps Lab ")
    print(f"============================================================")
    print(f"[*] Starting local security portal on http://localhost:{PORT}")
    print(f"[*] Press Ctrl+C to stop the server.")
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        try:
            webbrowser.open(f"http://localhost:{PORT}")
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server shutdown gracefully.")
            sys.exit(0)

if __name__ == '__main__':
    main()
