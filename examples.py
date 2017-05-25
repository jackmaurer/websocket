#!/usr/bin/env python
#
# MIT License
#
# Copyright (c) 2017 Jack Maurer
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Demonstrative code snippets."""

from socketserver import ThreadingTCPServer, ThreadingMixIn
import http.server

import websocket.server

class EchoHandler(websocket.server.WebSocketHandler):
    def handle_text(self):
        self.send_text(self.data)
    def handle_bin(self):
        self.send_bin(self.data)

def run():
    """Bind an echo server to localhost:8000.

    Deployment is the same as with http.server. Note that, due to the
    persistent nature of connections in the WebSocket protocol, it is
    advised that you use a multithreaded server for your applications.

    """
    HOST, PORT = "localhost", 8000
    with ThreadingTCPServer((HOST, PORT), EchoHandler) as server:
        print("Serving on port", PORT)
        server.serve_forever()

if __name__ == "__main__":
    run()

# Here's an example of a reverse proxy that serves both HTTP and
# WebSocket requests by detecting WebSocket handshakes and invoking
# the appropriate method of websocket.server.WebSocketHandler:

class ThreadingHTTPServer(http.server.HTTPServer, ThreadingMixIn):
    pass

class ReverseProxyHandler(websocket.server.WebSocketHandler,
                          http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.is_handshake():
            websocket.server.WebSocketHandler.do_GET(self)
        else:
            http.server.SimpleHTTPRequestHandler.do_GET(self)
