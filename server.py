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

"""WebSocket server classes."""

# RFE:
# - Extensions
#   - Sec-WebSocket-Extensions header
#   - Extension data
#
# IDEA: Could easily be ported to a WSGI application...

__all__ = [
    "CONNECTING", "OPEN", "CLOSING", "CLOSED",
    "WebSocketError", "WebSocketHandler", "DemoHandler"
]

import http.server
import http
import struct
import hashlib
import base64

import websocket.framing

CONNECTING, OPEN, CLOSING, CLOSED = range(4)
# Handler states

class WebSocketError(Exception):
    """Protocol breach by the client."""
    pass

class WebSocketHandler(http.server.BaseHTTPRequestHandler):
    """Base handler class for WebSocket requests.

    Attributes:
        state: An integer value indicating the present state of the
            handler instance.
        msg: A list of zero or more frames of the incoming message
            that is currently being processed.
        supported_subprotocols: A list of subprotocols supported by the
            handler class.
        subprotocols: A list of the subprotocols being used by the
            handler instance.

    """
    def handle_open(self):
        """Called following a successful handshake."""
        pass

    def handle_text(self):
        """Called when a textual data frame is received."""
        pass

    def handle_bin(self):
        """Called when a binary data frame is received."""
        pass

    def send_text(self, data, **kwargs):
        """Send a textual data frame.

        Args:
            data: A UTF-8 string containing payload data.
            **kwargs: Keyword arguments to pass to the
                websocket.framing.WebSocketFrame constructor.

        """
        frame = websocket.framing.WebSocketFrame(
            websocket.framing.TEXT, data.encode(), **kwargs
        )
        self.send_message((frame,))

    def send_bin(self, data, **kwargs):
        """Send a binary data frame.

        Args:
            data: A bytes-like object containing payload data.
            **kwargs: Keyword arguments to pass to the
                websocket.websocket.framing.WebSocketFrame constructor.

        """
        frame = websocket.framing.WebSocketFrame(
            websocket.framing.BINARY, data, **kwargs
        )
        self.send_message((frame,))

    def close(self, code=None, reason="", **kwargs):
        """Close the connection.

        For a list of status codes and their meanings, see
        https://tools.ietf.org/html/rfc6455#section-7.4.1

        Args:
            code: A status code to send the client (optional).
            reason: A UTF-8 string containing a reason for closing the
                connection (optional).
            **kwargs: Keyword arguments to pass to the
                websocket.framing.WebSocketFrame constructor.

        """
        self.state = CLOSING
        if code is not None:
            data = struct.pack("!H", code) + reason.encode()
        else:
            data = b""
        frame = websocket.framing.WebSocketFrame(websocket.framing.CLOSE,
                                                 data, **kwargs)
        self.send_message((frame,))
        if not self.msg or self.msg[0].opcode != websocket.framing.CLOSE:
            # The closing handshake was initiated by the server (us)
            self.handle_message()

    def do_GET(self):
        if self.is_handshake():
            try:
                self.send_handshake()
            except WebSocketError as error:
                self.send_error(http.HTTPStatus.BAD_REQUEST, str(error))
            else:
                # Request is kosher; begin receiving messages
                self.state = OPEN
                self.msg = []
                self.handle_open()
                while self.state == OPEN:
                    try:
                        self.handle_frame()
                    except WebSocketError as error:
                        self.log_error("WebSocketError: %s", error)
                        self.close(1002, str(error))
        else:
            self.send_error(http.HTTPStatus.UPGRADE_REQUIRED)
            # IDEA: Should this send a different error if there is an
            # upgrade header but its value is not 'websocket'

    def is_handshake(self):
        return (self.headers.get("Upgrade", "").strip().lower()
                == "websocket"
                and self.headers.get("Connection", "").strip().lower()
                == "upgrade") # should header names be lowercase?

    def send_handshake(self):
        """Respond to an opening handshake.

        Raises:
            WebSocketError: Invalid request headers.

        """
        key = self.headers.get("Sec-WebSocket-Key", "").strip()
        if not key:
            raise WebSocketError("Client must include Sec-WebSocket-Key")
        version = self.headers.get("Sec-WebSocket-Version", "").strip()
        if not version:
            raise WebSocketError("Client must include Sec-WebSocket-Version")
        elif version != "13":
            raise WebSocketError("Sec-WebSocket-Version must be 13")
        self.send_response(http.HTTPStatus.SWITCHING_PROTOCOLS)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", self.make_accept(key))
        self.subprotocols = []
        for value in self.headers.get_all("Sec-WebSocket-Protocol", []):
            for s in value.split(","):
                s = s.strip()
                if s in self.supported_subprotocols:
                    self.subprotocols.append(s)
        # Use all supported subprotocols from the request
        if self.subprotocols:
            self.send_header("Sec-WebSocket-Protocol",
                             ", ".join(self.subprotocols))
        self.end_headers()
        # TODO: Origin verification

    supported_subprotocols = []

    def handle_frame(self):
        """Receive and process an individual frame.

        Raises:
            WebSocketError: Invalid frame format.

        """
        try:
            self.parse_frame()
        except IndexError:
            raise
        if (len(self.msg) > 1
                and self.frame.opcode != websocket.framing.CONTINUE):
            raise WebSocketError(
                "Expected continuation frame following frame with "
                "FIN bit clear"
            )
        if self.msg[0].opcode == websocket.framing.TEXT:
            try:
                self.frame.data = self.frame.data.decode()
            except UnicodeDecodeError:
                self.close(1007)
            if self.frame.fin:
                self.handle_text()
        elif self.msg[0].opcode == websocket.framing.BINARY:
            if self.frame.fin:
                self.handle_bin()
        elif self.msg[0].opcode == websocket.framing.CLOSE:
            # TODO: FIN should be 0x1
            self.frame.reason = ""
            if self.frame.data:
                self.frame.code = struct.unpack("!H", self.frame.data[0:2])[0]
                if len(self.frame.data) > 2:
                    try:
                        self.frame.reason = self.frame.data[2:].decode()
                    except UnicodeDecodeError:
                        self.close(1007)
            else:
                self.frame.code = None
            if self.state == OPEN:
                self.close(self.frame.code, self.frame.reason)
        elif self.msg[0].opcode == websocket.framing.PING:
            # TODO: FIN should be 0x1
            self.send_message(websocket.framing.PONG, self.frame.data)
        elif self.msg[0].opcode == websocket.framing.PONG:
            pass
        else:
            raise WebSocketError(
                "unknown opcode: {}".format(hex(self.msg.opcode))
            )
        print("{} - {}".format(self.client_address[0], repr(self.frame.data)))
        if self.frame.fin:
            self.msg = []

    def parse_frame(self):
        self.frame = websocket.framing.parse_frame(self.rfile)
        if not self.frame.mask:
            raise WebSocketError("Messages from the client to the server "
                                 "must be masked")
        self.msg.append(self.frame)

    def send_message(self, msg):
        for frame in msg:
            self.wfile.write(frame.unparse())

    def setup(self):
        super().setup()
        self.state = CONNECTING

    def finish(self):
        super().finish()
        self.state = CLOSED

    @staticmethod
    def make_accept(key):
        """Generate the accept value corresponding to a given key.

        Args:
            key: The value of the Sec-WebSocket-Key request header
                field.

        Returns:
            A base64-encoded string representing the value of the
            Sec-WebSocket-Accept response header field.

        """
        guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        sha1 = hashlib.sha1((key + guid).encode()).digest()
        return base64.b64encode(sha1).decode()
