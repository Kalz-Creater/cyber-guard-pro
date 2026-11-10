"""
KALZ Threat Defense - High-Performance Multi-Threaded Local Server
Uses ThreadingHTTPServer for zero-latency concurrent asset delivery.
"""
import http.server
import socketserver
import webbrowser
import os
import sys

PORT = 8080

class OptimizedHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def end_headers(self):
        # Enable CORS for local modules
        self.send_header('Access-Control-Allow-Origin', '*')
        
        # Don't cache HTML so development edits show immediately,
        # but allow caching for large images/assets to ensure maximum speed.
        if self.path.endswith('.html') or self.path == '/' or self.path == '':
            self.send_header('Cache-Control', 'no-cache, must-revalidate')
        else:
            self.send_header('Cache-Control', 'public, max-age=3600')
            
        super().end_headers()

    def log_message(self, format, *args):
        # Clean formatted output without spamming console
        code = str(args[1]) if len(args) > 1 else '200'
        color = '\033[92m' if code.startswith('2') else ('\033[93m' if code.startswith('3') else '\033[91m')
        reset = '\033[0m'
        print(f"[{color}{code}{reset}] {args[0]}")

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("=" * 62)
    print("  KALZ // Cyber Threat Intelligence & DevSecOps Platform  ")
    print("=" * 62)
    print(f"[*] Multi-threaded server listening on http://localhost:{PORT}")
    print("[*] High-speed concurrent worker threads active.")
    print("[*] Press Ctrl+C to terminate.")

    # Use ThreadingHTTPServer for true multi-threaded parallel requests
    # Prevents blocking when loading large assets (like hero images/scripts)
    server_class = getattr(http.server, 'ThreadingHTTPServer', None)
    if not server_class:
        class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
        server_class = ThreadingHTTPServer

    server_class.allow_reuse_address = True

    try:
        with server_class(("", PORT), OptimizedHandler) as httpd:
            try:
                webbrowser.open(f"http://localhost:{PORT}")
            except Exception:
                pass
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server shutdown gracefully.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Server error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
