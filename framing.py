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

__all__ = ["parse_frame", "unparse_msg"]

import struct

def parse_frame(file):
    """Read and decode a frame from a file-like object"""
    parts = {}
    raw_frame = bytearray()
    raw_frame.extend(file.read(2))
    parts["fin"] = raw_frame[0] & 0x80
    parts["rsv1"] = raw_frame[0] & 0x40
    parts["rsv2"] = raw_frame[0] & 0x20
    parts["rsv3"] = raw_frame[0] & 0x10
    parts["opcode"] = raw_frame[0] & 0xf
    parts["mask"] = raw_frame[1] & 0x80
    parts["payload_len"] = raw_frame[1] & 0x7f
    if parts["payload_len"] > 125:
        if parts["payload_len"] == 126:
            raw_frame.extend(file.read(2))
            parts["payload_len"] = struct.unpack("!H", raw_frame[2:4])
        else:
            # 127
            raw_frame.extend(file.read(8))
            parts["payload_len"] = struct.unpack("!Q", raw_frame[2:10])
            # TODO: Check if most sig bit is 0
    if parts["mask"]:
        parts["masking_key"] = file.read(4)
        raw_frame.extend(parts["masking_key"])
    masked_data = file.read(parts["payload_len"])
    raw_frame.extend(masked_data)
    if parts["mask"]:
        parts["data"] = bytearray()
        for i, byte in enumerate(masked_data):
            parts["data"].append(byte ^ parts["masking_key"][i % 4])
    else:
        parts["data"] = masked_data
    parts["raw_frame"] = raw_frame
    return parts

def unparse_msg(file, opcode, data, fin, rsv1, rsv2, rsv3, mask=0,
                masking_key=None):
    """Encode a message and write it to a file-like object"""
    frame = bytearray()
    frame.append(fin << 7 | rsv1 << 6 | rsv2 << 5 | rsv3 << 4 | opcode)
    frame.append(mask << 7 | len(data))
    # TODO: Payload lengths greater than 125
    # TODO: Masking
    frame.extend(data)
    file.write(frame)
    return frame
