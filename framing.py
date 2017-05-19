"""Functions for encoding and decoding data in the WebSocket protocol

Frame format (RFC 6455):

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+

"""

__all__ = ["CONTINUE", "TEXT", "BINARY", "CLOSE", "PING", "PONG",
           "WebSocketFrame", "parse_frame"]

import struct

CONTINUE, TEXT, BINARY, CLOSE, PING, PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xa
# Opcodes

class WebSocketFrame(object):
    def __init__(self, opcode=None, data=None, fin=1, rsv1=0, rsv2=0, rsv3=0,
                 mask=0, masking_key=None):
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv2 = rsv2
        self.rsv3 = rsv3
        self.opcode = opcode
        self.mask = mask
        self.masking_key = masking_key
        self.data = data

    def unparse(self):
        """Encode to a bytearrray object"""
        frame = bytearray()
        frame.append(self.fin << 7
                     | self.rsv1 << 6
                     | self.rsv2 << 5
                     | self.rsv3 << 4
                     | self.opcode)
        frame.append(self.mask << 7 | len(self.data))
        # TODO: Payload lengths greater than 125
        # TODO: Masking
        frame.extend(self.data)
        return frame

def parse_frame(file):
    """Read and decode a frame from a file-like object"""
    frame = WebSocketFrame()
    raw_frame = bytearray()
    raw_frame.extend(file.read(2))
    frame.fin = raw_frame[0] & 0x80
    frame.rsv1 = raw_frame[0] & 0x40
    frame.rsv2 = raw_frame[0] & 0x20
    frame.rsv3 = raw_frame[0] & 0x10
    frame.opcode = raw_frame[0] & 0xf
    frame.mask = raw_frame[1] & 0x80
    frame.payload_len = raw_frame[1] & 0x7f
    if frame.payload_len > 125:
        if frame.payload_len == 126:
            raw_frame.extend(file.read(2))
            frame.payload_len = struct.unpack("!H", raw_frame[2:4])
        else:
            # 127
            raw_frame.extend(file.read(8))
            frame.payload_len = struct.unpack("!Q", raw_frame[2:10])
            # TODO: Check if most sig bit is 0
    if frame.mask:
        frame.masking_key = file.read(4)
        raw_frame.extend(frame.masking_key)
    masked_data = file.read(frame.payload_len)
    raw_frame.extend(masked_data)
    if frame.mask:
        frame.data = bytearray()
        for i, byte in enumerate(masked_data):
            frame.data.append(byte ^ frame.masking_key[i % 4])
    else:
        frame.data = masked_data
    return frame#, raw_frame
