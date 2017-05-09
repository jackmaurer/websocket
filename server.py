"""Extensible WebSocket Server"""

# RFE:
# - Extensions
#   - Sec-WebSocket-Extensions header
#   - Extension data
#
# TODO:
# - Catch UnicodeDecodeError when decoding UTF-8 payload data and fail
#   the connection (code 1007)

import socketserver
import http.server
import http
import sys
import struct
import hashlib
import base64

import framing

CONNECTING, OPEN, CLOSING, CLOSED = range(4)

CONTINUE, TEXT, BINARY, CLOSE, PING, PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xa

class WebSocketError(Exception):
    """Protocol breach by the client"""
    pass

class WebSocketServer(socketserver.ThreadingTCPServer):
    """Multithreaded TCP server that keeps track of clients"""
    def __init__(self, *args, **kwargs):
        self.handlers = []
        socketserver.ThreadingTCPServer.__init__(self, *args, **kwargs)

class WebSocketHandler(http.server.BaseHTTPRequestHandler):
    """Handler for WebSocket requests"""
    supported_subprotocols =  []

    def handle_text(self):
        """Called when a textual data frame is received"""
        pass

    def handle_bin(self):
        """Called when a binary data frame is received"""
        pass

    def send_text(self, data, **kwargs):
        """Send a textual data frame"""
        self.send_message(TEXT, data.encode(), **kwargs)

    def send_bin(self, data, **kwargs):
        """Send a binary data frame"""
        self.send_message(BINARY, data, **kwargs)

    def close(self, code=None, reason="", **kwargs):
        """Close the connection

        For a list of status codes and their meanings, see
        https://tools.ietf.org/html/rfc6455#section-7.4.1

        """
        self.state = CLOSING
        if code is not None:
            data = struct.pack("!H", code) + reason.encode()
        else:
            data = b""
        self.send_message(CLOSE, data, **kwargs)
        if self.opcode != CLOSE:
            self.handle_message()

    def do_GET(self):
        if (self.headers.get("Upgrade", "").strip().lower()
                == "websocket"
                and self.headers.get("Connection", "").strip().lower()
                == "upgrade"):
            try:
                self.send_handshake()
            except WebSocketError as error:
                print("WebSocketError:", error, file=sys.stderr)
                self.send_error(http.HTTPStatus.BAD_REQUEST, str(error))
            else:
                self.state = OPEN
                self.server.handlers.append(self)
                while self.state == OPEN:
                    try:
                        self.handle_frame()
                    except WebSocketError as error:
                        self.close(1002, str(error))
        else:
            self.send_error(http.HTTPStatus.UPGRADE_REQUIRED)

    def send_handshake(self):
        key = self.headers.get("Sec-WebSocket-Key", "").strip()
        if key:
            version = self.headers.get("Sec-WebSocket-Version", "").strip()
            if version:
                if version != "13":
                    raise WebSocketError("Sec-WebSocket-Version must be 13")
                self.send_response(http.HTTPStatus.SWITCHING_PROTOCOLS)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", self.make_accept(key))
                self.subprotocols = []
                for value in self.headers.get_all("Sec-WebSocket-Protocol",
                                                   []):
                    for s in value.split(","):
                        s = s.strip()
                        if s in self.supported_subprotocols:
                            self.subprotocols.append(s)
                if self.subprotocols:
                    self.send_header("Sec-WebSocket-Protocol",
                                     ", ".join(self.subprotocols))
                self.end_headers()
                # TODO: Origin verification
            else:
                raise WebSocketError("Client must include "
                                     "Sec-WebSocket-Version")
        else:
            raise WebSocketError("Client must include Sec-WebSocket-Key")

    def handle_frame(self):
        self.parse_frame()
        if self.opcode == CONTINUE:
            # RFE: Message fragmentation
            pass
        elif self.opcode == TEXT:
            self.data = self.data.decode()
            self.handle_text()
        elif self.opcode == BINARY:
            self.handle_bin()
        elif self.opcode == CLOSE:
            self.reason = ""
            if self.data:
                self.code = struct.unpack("!H", self.data[0:2])
                if len(self.data) > 2:
                    self.reason = self.data[2:].decode()
            else:
                self.code = None
            if self.state == OPEN:
                self.close(self.code, self.reason)
        elif self.opcode == PING:
            self.send_message(PONG, self.data)
        elif self.opcode == PONG:
            pass
        else:
            raise WebSocketError("unknown opcode: {}".format(hex(self.opcode)))

    def parse_frame(self):
        parts = framing.parse_frame(self.rfile)
        if not parts["mask"]:
            raise WebSocketError("Messages from the client to the server must "
                                 "be masked")
        for name in parts:
            setattr(self, name, parts[name])

    def send_message(self, opcode, data, fin=1, rsv1=0, rsv2=0, rsv3=0):
        framing.unparse_msg(self.wfile, opcode, data, fin, rsv1, rsv2, rsv3)

    def setup(self):
        http.server.BaseHTTPRequestHandler.setup(self)
        self.state = CONNECTING

    def finish(self):
        http.server.BaseHTTPRequestHandler.finish(self)
        self.state = CLOSED
        if self in self.server.handlers:
            self.server.handlers.remove(self)

    @staticmethod
    def make_accept(key):
        """Generate the value of the Sec-WebSocket-Accept header field

        This is done by concatenating the value of the Sec-WebSocket-Key
        header field with a Globally Unique Indentifier (GUID) and
        taking the base64-encoded SHA1 hash of this value.

        """
        guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        sha1 = hashlib.sha1((key + guid).encode()).digest()
        return base64.b64encode(sha1).decode()

class DemoHandler(WebSocketHandler):
    def handle_text(self):
        self.send_text(self.data)
    def handle_bin(self):
        self.send_bin(self.data)

if __name__ == "__main__":
    HOST, PORT = ("localhost", 8000)
    with WebSocketServer((HOST, PORT), DemoHandler) as server:
        print("Serving on port", PORT)
        server.serve_forever()
