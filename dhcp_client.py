#!/usr/bin/env python3
"""
dhcp_client.py - ITT440 DHCP client (runs in Windows cmd, also works on Linux).

Performs the DORA exchange against our own server and then offers a small menu:
    r = renew the lease (unicast REQUEST)    i = DHCPINFORM
    x = release the lease                    q = quit

NOTE: it shows what the server leased but does NOT change the Windows network
adapter (that would need admin rights and could cut your own internet).

Examples
  python dhcp_client.py --server 172.20.10.5 --server-port 6767 --client-port 6868
  python dhcp_client.py                      # real LAN: broadcast on 67/68
"""
import argparse
import random
import socket
import struct
import sys
import time
import uuid

from dhcp_common import *

PARAMS = bytes([OPT_SUBNET, OPT_ROUTER, OPT_DNS, OPT_DOMAIN, OPT_BROADCAST,
                OPT_LEASE, OPT_SERVER_ID, OPT_T1, OPT_T2])


def default_mac():
    n = uuid.getnode()
    return ":".join(f"{(n >> s) & 0xff:02x}" for s in range(40, -1, -8))


def summarize(pkt):
    o = pkt["options"]

    def ips(code):
        b = o.get(code, b"")
        return [bytes_to_ip(b[i:i + 4]) for i in range(0, len(b) - 3, 4)]

    def secs(code):
        return struct.unpack("!I", o[code])[0] if len(o.get(code, b"")) == 4 else None

    return {"ip": pkt["yiaddr"], "mask": (ips(OPT_SUBNET) or [None])[0],
            "router": (ips(OPT_ROUTER) or [None])[0], "dns": ips(OPT_DNS),
            "domain": o.get(OPT_DOMAIN, b"").decode(errors="replace"),
            "server": (ips(OPT_SERVER_ID) or [None])[0],
            "lease": secs(OPT_LEASE), "t1": secs(OPT_T1), "t2": secs(OPT_T2)}


class DhcpClient:
    def __init__(self, a):
        self.a = a
        self.mac = (a.mac or default_mac()).lower().replace("-", ":")
        self.hostname = a.hostname or socket.gethostname()
        self.lease = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            self.sock.bind(("", a.client_port))
        except OSError as e:
            sys.exit(f"Cannot bind UDP {a.client_port}: {e}\n"
                     "On Windows port 68 is often used by the DHCP Client service - "
                     "try --client-port 6868 (and --server-port 6767).")

    # ---- low level ----
    def target(self):
        if self.a.server:
            return (self.a.server, self.a.server_port)
        return ("255.255.255.255", self.a.server_port)

    def send(self, msg_type, xid, extra=(), ciaddr="0.0.0.0", dest=None):
        broadcast = dest is None and not self.a.server
        opts = [(OPT_MSGTYPE, bytes([msg_type])),
                (OPT_CLIENT_ID, b"\x01" + mac_to_bytes(self.mac)),
                (OPT_HOSTNAME, self.hostname.encode()),
                (OPT_PARAM_REQ, PARAMS)] + list(extra)
        pkt = build_packet(BOOTREQUEST, xid, 0x8000 if broadcast else 0, ciaddr,
                           "0.0.0.0", "0.0.0.0", "0.0.0.0", self.mac, opts)
        dest = dest or self.target()
        self.sock.sendto(pkt, dest)
        print(f"  -> DHCP{MSG_NAMES[msg_type]} sent to {dest[0]}:{dest[1]}")

    def wait(self, xid, want, timeout):
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                return None
            self.sock.settimeout(left)
            try:
                data, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                return None
            except ConnectionResetError:       # Windows: ICMP "port unreachable"
                continue
            pkt = parse_packet(data)
            if pkt and pkt["op"] == BOOTREPLY and pkt["xid"] == xid \
                    and pkt["mac"] == self.mac and pkt["msg_type"] in want:
                return pkt

    # ---- protocol steps ----
    def acquire(self):
        xid = random.getrandbits(32)
        print(f"\nMAC {self.mac}  hostname {self.hostname}  xid {xid:08x}")
        offer = None
        for attempt in range(1, 5):                           # D + O
            print(f"[{attempt}/4] Discover")
            extra = [(OPT_REQ_IP, ip_to_bytes(self.a.request_ip))] if self.a.request_ip else []
            self.send(DISCOVER, xid, extra)
            offer = self.wait(xid, {OFFER}, 2 * attempt)
            if offer:
                break
            print("  .. no offer, retrying")
        if not offer:
            print("No DHCPOFFER received. Is the server running and reachable?")
            return False
        info = summarize(offer)
        print(f"  <- DHCPOFFER: {info['ip']} from server {info['server']}")

        for attempt in range(1, 4):                           # R + A
            self.send(REQUEST, xid, [(OPT_REQ_IP, ip_to_bytes(info["ip"])),
                                     (OPT_SERVER_ID, ip_to_bytes(info["server"]))])
            ack = self.wait(xid, {ACK, NAK}, 3)
            if ack:
                break
        else:
            print("No reply to DHCPREQUEST.")
            return False
        if ack["msg_type"] == NAK:
            msg = ack["options"].get(OPT_MESSAGE, b"").decode(errors="replace")
            print(f"  <- DHCPNAK: {msg}")
            return False
        self.lease = summarize(ack)
        self.lease["acquired"] = time.time()
        print("  <- DHCPACK")
        self.show()
        return True

    def renew(self):
        if not self.lease:
            return print("No lease to renew.")
        xid = random.getrandbits(32)
        dest = (self.a.server or self.lease["server"], self.a.server_port)
        self.send(REQUEST, xid, ciaddr=self.lease["ip"], dest=dest)
        ack = self.wait(xid, {ACK, NAK}, 4)
        if ack and ack["msg_type"] == ACK:
            self.lease = summarize(ack)
            self.lease["acquired"] = time.time()
            print("  <- DHCPACK (lease renewed)")
            self.show()
        else:
            print("  Renewal failed (NAK or timeout).")

    def inform(self):
        if not self.lease:
            return print("No lease yet.")
        xid = random.getrandbits(32)
        dest = (self.a.server or self.lease["server"], self.a.server_port)
        self.send(INFORM, xid, ciaddr=self.lease["ip"], dest=dest)
        ack = self.wait(xid, {ACK}, 4)
        if ack:
            i = summarize(ack)
            print(f"  <- DHCPACK (config only): router {i['router']}, dns {i['dns']}")
        else:
            print("  No reply.")

    def release(self):
        if not self.lease:
            return print("No lease to release.")
        dest = (self.a.server or self.lease["server"], self.a.server_port)
        self.send(RELEASE, random.getrandbits(32), [(OPT_SERVER_ID, ip_to_bytes(self.lease["server"]))],
                  ciaddr=self.lease["ip"], dest=dest)
        print(f"  Released {self.lease['ip']}.")
        self.lease = None

    def show(self):
        l = self.lease
        print("\n  ----- LEASE -----")
        print(f"  IP address : {l['ip']}")
        print(f"  Subnet mask: {l['mask']}")
        print(f"  Gateway    : {l['router']}")
        print(f"  DNS        : {', '.join(l['dns'])}")
        print(f"  Domain     : {l['domain']}")
        print(f"  DHCP server: {l['server']}")
        print(f"  Lease time : {l['lease']}s  (T1 renew {l['t1']}s, T2 rebind {l['t2']}s)")
        print("  -----------------\n")

    def menu(self):
        while True:
            try:
                c = input("[r]enew  [i]nform  [x] release  [q]uit > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                c = "q"
            if c == "r":
                self.renew()
            elif c == "i":
                self.inform()
            elif c == "x":
                self.release()
            elif c == "q":
                if self.lease and self.a.release_on_exit:
                    self.release()
                return


def main():
    p = argparse.ArgumentParser(description="Simple DHCP client (ITT440)")
    p.add_argument("--server", default=None, help="server IP (omit = broadcast)")
    p.add_argument("--server-port", type=int, default=67)
    p.add_argument("--client-port", type=int, default=68)
    p.add_argument("--mac", default=None, help="fake MAC to test several clients")
    p.add_argument("--hostname", default=None)
    p.add_argument("--request-ip", default=None, help="ask for a specific IP (server may refuse)")
    p.add_argument("--no-menu", action="store_true", help="get a lease and exit")
    p.add_argument("--release-on-exit", action="store_true")
    a = p.parse_args()
    c = DhcpClient(a)
    if c.acquire() and not a.no_menu:
        c.menu()


if __name__ == "__main__":
    main()
