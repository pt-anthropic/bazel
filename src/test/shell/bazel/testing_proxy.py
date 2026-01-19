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

The proxy reads credentials from environment variables and can forward
requests to an upstream proxy.

Environment variables:
  PROXY_AUTH_USER: Username for proxy authentication (default from upstream proxy URL)
  PROXY_AUTH_PASS: Password for proxy authentication (default from upstream proxy URL)
  UPSTREAM_PROXY: Upstream proxy URL to forward requests to (defaults to http_proxy/https_proxy)

Usage:
  python testing_proxy.py [--port PORT] [--auth]

Options:
  --port: Port for the proxy to listen on (default: random available port)
  --auth: Require proxy authentication
"""

import argparse
import base64
import http.client
import os
import random
import socket
import ssl
import sys
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import urlparse


class TCPServerV6(TCPServer):
    address_family = socket.AF_INET6


def parse_proxy_url(proxy_url):
    """Parse a proxy URL and extract host, port, username, password."""
    if not proxy_url:
        return None, None, None, None

    parsed = urlparse(proxy_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    username = parsed.username
    password = parsed.password

    return host, port, username, password


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP Proxy handler that properly returns 407 for proxy auth failures.

    This proxy forwards client credentials to the upstream proxy rather than
    validating them locally. This allows testing that Bazel correctly sends
    proxy credentials.
    """

    auth_required = False
    upstream_proxy_host = None
    upstream_proxy_port = None

    @classmethod
    def configure(cls, auth_required, upstream_proxy_url):
        """Configure the proxy handler from environment and arguments."""
        cls.auth_required = auth_required

        # Parse upstream proxy URL (only need host:port, credentials come from client)
        host, port, _, _ = parse_proxy_url(upstream_proxy_url)
        cls.upstream_proxy_host = host
        cls.upstream_proxy_port = port
        # Don't store upstream_proxy_auth - we'll forward the client's credentials
        cls.upstream_proxy_auth = None

    def do_CONNECT(self):
        """Handle CONNECT method for HTTPS tunneling."""
        if self.auth_required and not self._check_proxy_auth():
            return

        # Parse the target host:port from the CONNECT request
        # self.path is like "bcr.bazel.build:443"
        target = self.path
        if ':' in target:
            target_host, target_port_str = target.rsplit(':', 1)
            target_port = int(target_port_str)
        else:
            target_host = target
            target_port = 443

        try:
            if self.upstream_proxy_host:
                # Connect to upstream proxy
                upstream_sock = socket.create_connection(
                    (self.upstream_proxy_host, self.upstream_proxy_port), timeout=30)

                # Send CONNECT request to upstream proxy
                # Use the original target string which already has host:port
                connect_req = f'CONNECT {target} HTTP/1.1\r\n'
                connect_req += f'Host: {target}\r\n'
                # Forward client's credentials to upstream
                if hasattr(self, '_client_proxy_auth') and self._client_proxy_auth:
                    connect_req += f'Proxy-Authorization: {self._client_proxy_auth}\r\n'
                connect_req += '\r\n'
                upstream_sock.sendall(connect_req.encode())

                # Read response from upstream proxy
                response = b''
                while b'\r\n\r\n' not in response:
                    chunk = upstream_sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk

                # Check if upstream accepted the CONNECT
                status_line = response.split(b'\r\n')[0].decode()
                if ' 200 ' not in status_line:
                    self.send_error(502, f'Upstream proxy error: {status_line}')
                    upstream_sock.close()
                    return

                target_sock = upstream_sock
            else:
                # Direct connection to target
                target_sock = socket.create_connection((target_host, target_port), timeout=30)

            # Tell client the tunnel is established
            self.send_response(200, 'Connection established')
            self.end_headers()

            # Tunnel data between client and target
            self._tunnel(self.connection, target_sock)

        except Exception as e:
            self.send_error(502, f'Tunnel error: {e}')

    def _tunnel(self, client_sock, target_sock):
        """Tunnel data between two sockets."""
        import select
        sockets = [client_sock, target_sock]
        timeout = 60

        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, timeout)

                if exceptional:
                    break

                if not readable:
                    break

                for sock in readable:
                    other = target_sock if sock is client_sock else client_sock
                    try:
                        data = sock.recv(8192)
                        if not data:
                            return
                        other.sendall(data)
                    except:
                        return
        finally:
            target_sock.close()

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
        """Check Proxy-Authorization header and return 407 if missing.

        This proxy forwards the client's credentials to the upstream proxy,
        rather than validating them locally. It only checks if credentials
        are present.

        Returns:
            True if credentials are present, False otherwise.
        """
        auth_header = self.headers.get('Proxy-Authorization', '')

        if auth_header:
            # Store for forwarding to upstream
            self._client_proxy_auth = auth_header
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
        """Forward requests to target server or upstream proxy after auth check."""
        if not self.client_address:
            self.client_address = 'localhost'

        if self.auth_required and not self._check_proxy_auth():
            return

        # Parse the request URL
        parsed = urlparse(self.path)
        target_host = parsed.hostname
        target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        try:
            if self.upstream_proxy_host:
                # Forward through upstream proxy
                conn = http.client.HTTPConnection(
                    self.upstream_proxy_host, self.upstream_proxy_port, timeout=30)

                # Build headers
                headers = {}
                hop_by_hop = {'connection', 'keep-alive', 'proxy-authenticate',
                             'proxy-authorization', 'te', 'trailers',
                             'transfer-encoding', 'upgrade'}
                for key, value in self.headers.items():
                    if key.lower() not in hop_by_hop:
                        headers[key] = value

                # Forward client's credentials to upstream
                if hasattr(self, '_client_proxy_auth') and self._client_proxy_auth:
                    headers['Proxy-Authorization'] = self._client_proxy_auth

                # Read body for POST requests
                body = None
                if method == 'POST':
                    content_length = int(self.headers.get('Content-Length', 0))
                    if content_length > 0:
                        body = self.rfile.read(content_length)

                # Send full URL for proxy request
                conn.request(method, self.path, body=body, headers=headers)
            else:
                # Direct connection to target
                if parsed.scheme == 'https':
                    context = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(target_host, target_port,
                                                        timeout=30, context=context)
                else:
                    conn = http.client.HTTPConnection(target_host, target_port, timeout=30)

                # Build headers
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
            hop_by_hop = {'connection', 'keep-alive', 'proxy-authenticate',
                         'proxy-authorization', 'te', 'trailers',
                         'transfer-encoding', 'upgrade'}
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
    parser.add_argument('--upstream', type=str, default=None,
                       help='Upstream proxy URL (defaults to http_proxy env var)')
    args = parser.parse_args(argv)

    # Determine upstream proxy URL
    upstream_proxy = args.upstream
    if not upstream_proxy:
        upstream_proxy = os.environ.get('UPSTREAM_PROXY') or \
                        os.environ.get('http_proxy') or \
                        os.environ.get('HTTP_PROXY')

    # Configure the handler
    ProxyHandler.configure(args.auth, upstream_proxy)

    if upstream_proxy:
        sys.stderr.write(f'Upstream proxy: {upstream_proxy[:50]}...\n')

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
