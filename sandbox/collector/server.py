#!/usr/bin/env python3
"""Canary collector: records hits in memory; GET /hits returns JSON."""
import json, time, sys
from http.server import HTTPServer, BaseHTTPRequestHandler

HITS = []

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default logging

    def do_GET(self):
        if self.path == '/hits' or self.path.startswith('/hits?'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(HITS).encode())
            return
        # any other request = receipt
        self.record('GET')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'CANARY RECEIPT')

    def do_POST(self):
        if self.path == '/reset':
            HITS.clear()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{}')
            return
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace') if length else ''
        self.record('POST', body)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'CANARY RECEIPT')

    def record(self, method, body=''):
        HITS.append({
            'timestamp': time.time(),
            'method': method,
            'path': self.path,
            'query': self.path.split('?', 1)[1] if '?' in self.path else '',
            'headers': dict(self.headers),
            'body': body,
        })

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 65500
    server = HTTPServer(('0.0.0.0', port), Handler)
    server.serve_forever()
