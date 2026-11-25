"""
dhcp_common.py - shared helpers for the ITT440 DHCP server and client.

A DHCP message is a BOOTP packet (RFC 951) with a "magic cookie" and a list of
options (RFC 2131 / RFC 2132). This module only knows how to BUILD and PARSE
that packet; the server/client logic lives in the other two files.

Packet layout (bytes):
   0  op      1 = request (client->server), 2 = reply (server->client)
   1  htype   1 = Ethernet
   2  hlen    6 = MAC length
   3  hops
   4  xid     random id the client picks, used to match replies
   8  secs
  10  flags   0x8000 = "please reply by broadcast"
  12  ciaddr  client's current IP (only when renewing / releasing)
  16  yiaddr  "your" IP - the address the server is giving out
  20  siaddr  server IP
  24  giaddr  relay agent IP (not used here)
  28  chaddr  client MAC (16 bytes, padded)
  44  sname   64 bytes (unused)
 108  file    128 bytes (unused)
 236  magic   63 82 53 63
 240  options code | length | data ... 255 (end)
"""
import socket
import struct

MAGIC_COOKIE = b"\x63\x82\x53\x63"
HEADER_FMT = "!BBBBIHH4s4s4s4s"          # first 28 bytes
BOOTREQUEST, BOOTREPLY = 1, 2

# DHCP message types (option 53)
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)
MSG_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
             5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}

# Option codes we use
OPT_SUBNET, OPT_ROUTER, OPT_DNS = 1, 3, 6
OPT_HOSTNAME, OPT_DOMAIN, OPT_BROADCAST = 12, 15, 28
OPT_REQ_IP, OPT_LEASE, OPT_MSGTYPE, OPT_SERVER_ID = 50, 51, 53, 54
OPT_PARAM_REQ, OPT_MESSAGE, OPT_T1, OPT_T2, OPT_CLIENT_ID = 55, 56, 58, 59, 61

MIN_PACKET = 300                         # some stacks drop shorter packets


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def bytes_to_ip(b: bytes) -> str:
    return socket.inet_ntoa(b)


def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def bytes_to_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def encode_options(options) -> bytes:
    """options = list of (code, bytes). Adds the END marker (255)."""
    out = b""
    for code, data in options:
        out += bytes([code, len(data)]) + data
    return out + b"\xff"


def decode_options(data: bytes) -> dict:
    """Walk the TLV list and return {code: raw_bytes}."""
    opts, i = {}, 0
    while i < len(data):
        code = data[i]
        if code == 255:                  # END
            break
        if code == 0:                    # PAD
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        opts[code] = data[i + 2:i + 2 + length]
        i += 2 + length
    return opts


def build_packet(op, xid, flags, ciaddr, yiaddr, siaddr, giaddr, mac, options) -> bytes:
    header = struct.pack(HEADER_FMT, op, 1, 6, 0, xid, 0, flags,
                         ip_to_bytes(ciaddr), ip_to_bytes(yiaddr),
                         ip_to_bytes(siaddr), ip_to_bytes(giaddr))
    chaddr = mac_to_bytes(mac).ljust(16, b"\x00")
    packet = header + chaddr + b"\x00" * 64 + b"\x00" * 128 + MAGIC_COOKIE
    packet += encode_options(options)
    return packet.ljust(MIN_PACKET, b"\x00")


def parse_packet(data: bytes):
    """Return a dict, or None if this is not a DHCP packet."""
    if len(data) < 240 or data[236:240] != MAGIC_COOKIE:
        return None
    (op, htype, hlen, hops, xid, secs, flags,
     ciaddr, yiaddr, siaddr, giaddr) = struct.unpack(HEADER_FMT, data[:28])
    options = decode_options(data[240:])
    mt = options.get(OPT_MSGTYPE)
    return {
        "op": op, "xid": xid, "flags": flags,
        "ciaddr": bytes_to_ip(ciaddr), "yiaddr": bytes_to_ip(yiaddr),
        "siaddr": bytes_to_ip(siaddr), "giaddr": bytes_to_ip(giaddr),
        "mac": bytes_to_mac(data[28:28 + 6]),
        "options": options,
        "msg_type": mt[0] if mt else None,
    }
