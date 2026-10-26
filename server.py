import http.server
import socketserver
import webbrowser
import os

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

if __name__ == '__main__':
    print(f"=====================================================")
    print(f"🚀 MAY CHU WEB MAT MA HOC & AN TOAN THONG TIN DANG CHAY")
    print(f"📍 Dia chi: http://localhost:{PORT}")
    print(f"📁 Thu muc: {DIRECTORY}")
    print(f"=====================================================")
    
    # Tu dong mo trinh duyet
    webbrowser.open(f"http://localhost:{PORT}/index.html")
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDa dung may chu web.")
