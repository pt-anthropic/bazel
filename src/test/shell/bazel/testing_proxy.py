# Copyright 2015 The Bazel Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""An HTTP proxy server for testing proxy authentication.

This proxy returns the correct HTTP 407 Proxy Authentication Required status
code when authentication is needed, as specified in RFC 7235. This is distinct
from HTTP 401 Unauthorized which is used by origin servers.

Key differences:
- HTTP 401: Origin server authentication, uses WWW-Authenticate header
- HTTP 407: Proxy authentication, uses Proxy-Authenticate header

Usage:
  python testing_proxy.py [--port PORT] [--auth] [--target_host HOST] [--target_port PORT]

Options:
  --port: Port for the proxy to listen on (default: random available port)
  --auth: Require proxy authentication (valid credentials: foo:bar)
  --target_host: Backend server host (default: localhost)
  --target_port: Backend server port (required if --auth or forwarding)
"""

import argparse
import base64
import http.client
import random
import socket
import sys
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import urlparse


class TCPServerV6(TCPServer):
    address_family = socket.AF_INET6


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP Proxy handler that properly returns 407 for proxy auth failures."""

    auth_required = False
    target_host = 'localhost'
    target_port = 80
    valid_credentials = [
        b'Basic ' + base64.b64encode('foo:bar'.encode('ascii')),
    ]

    def do_CONNECT(self):
        """Handle CONNECT method for HTTPS tunneling."""
        if self.auth_required and not self._check_proxy_auth():
            return
        # For testing purposes, just acknowledge the CONNECT
        self.send_response(200, 'Connection established')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests through the proxy."""
        self._handle_request('GET')

    def do_POST(self):
        """Handle POST requests through the proxy."""
        self._handle_request('POST')

    def do_HEAD(self):
        """Handle HEAD requests through the proxy."""
        self._handle_request('HEAD')

    def _check_proxy_auth(self):
        """Check Proxy-Authorization header and return 407 if invalid.

        Returns:
            True if authentication passed or not required, False otherwise.
        """
        auth_header = self.headers.get('Proxy-Authorization', '').encode('ascii')

        if auth_header in self.valid_credentials:
            return True

        # Send HTTP 407 Proxy Authentication Required
        # This is the CORRECT response code for proxy auth failures
        # (not 401, which is for origin server auth)
        self.send_response(407)
        self.send_header('Proxy-Authenticate', 'Basic realm="Proxy"')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(
            b'<html><body><h1>407 Proxy Authentication Required</h1>'
            b'<p>This proxy requires authentication.</p>'
            b'<p>Use Proxy-Authorization header with valid credentials.</p>'
            b'</body></html>'
        )
        return False

    def _handle_request(self, method):
        """Forward requests to target server after auth check."""
        if not self.client_address:
            self.client_address = 'localhost'

        if self.auth_required and not self._check_proxy_auth():
            return

        # Parse the request URL
        parsed = urlparse(self.path)
        if parsed.netloc:
            # Absolute URL (proxy request)
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
        else:
            # Relative URL (use configured target)
            host = self.target_host
            port = self.target_port
            path = self.path

        try:
            # Forward request to target server
            conn = http.client.HTTPConnection(host, port, timeout=30)

            # Forward headers (excluding hop-by-hop headers)
            headers = {}
            hop_by_hop = {'connection', 'keep-alive', 'proxy-authenticate',
                         'proxy-authorization', 'te', 'trailers',
                         'transfer-encoding', 'upgrade'}
            for key, value in self.headers.items():
                if key.lower() not in hop_by_hop:
                    headers[key] = value

            # Read body for POST requests
            body = None
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    body = self.rfile.read(content_length)

            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()

            # Send response back to client
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in hop_by_hop:
                    self.send_header(key, value)
            self.end_headers()

            # Forward response body
            self.wfile.write(response.read())
            conn.close()

        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f'Proxy error: {e}'.encode('utf-8'))

    def log_message(self, format, *args):
        """Log to stderr."""
        sys.stderr.write('%s - - [%s] %s\n' %
                        (self.client_address[0] if isinstance(self.client_address, tuple)
                         else self.client_address,
                         self.log_date_time_string(),
                         format % args))


def main(argv):
    parser = argparse.ArgumentParser(description='HTTP Proxy for testing')
    parser.add_argument('--port', type=int, default=0,
                       help='Port to listen on (0 for random)')
    parser.add_argument('--auth', action='store_true',
                       help='Require proxy authentication')
    parser.add_argument('--target_host', default='localhost',
                       help='Backend server host')
    parser.add_argument('--target_port', type=int, default=80,
                       help='Backend server port')
    args = parser.parse_args(argv)

    ProxyHandler.auth_required = args.auth
    ProxyHandler.target_host = args.target_host
    ProxyHandler.target_port = args.target_port

    port = args.port
    httpd = None

    if port == 0:
        # Find a random available port
        while httpd is None:
            try:
                port = random.randrange(32760, 59760)
                if sys.platform == 'darwin':
                    httpd = TCPServerV6(('', port), ProxyHandler)
                else:
                    httpd = TCPServer(('', port), ProxyHandler)
            except socket.error:
                port = 0
    else:
        if sys.platform == 'darwin':
            httpd = TCPServerV6(('', port), ProxyHandler)
        else:
            httpd = TCPServer(('', port), ProxyHandler)

    # Output port for test scripts to capture
    sys.stdout.write('%d\nstarted\n' % port)
    sys.stdout.flush()
    sys.stdout.close()

    sys.stderr.write('Proxy server listening on port %d (auth=%s)\n' %
                    (port, args.auth))

    try:
        httpd.serve_forever()
    finally:
        sys.stderr.write('Proxy server shutting down.\n')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
