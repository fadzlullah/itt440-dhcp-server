#!/usr/bin/env python3
"""
dhcp_server.py - ITT440 DHCP server (runs on Linux / WSL).

Implements the DORA exchange from RFC 2131:
    DISCOVER -> OFFER -> REQUEST -> ACK
plus NAK, RELEASE, DECLINE and INFORM.

Extras: lease expiry, JSON lease file (survives restart), MAC reservations,
honours the client's Parameter Request List, live console ("leases" command).

Examples
  sudo python3 dhcp_server.py                             # real ports 67/68
  python3 dhcp_server.py --server-port 6767 --client-port 6868   # demo, no sudo
"""
import argparse
import ipaddress
import json
import logging
import os
import select
import socket
import struct
import sys
import time

from dhcp_common import *

log = logging.getLogger("dhcpd")


# --------------------------------------------------------------------------
# Lease database: decides which IP each MAC gets
# --------------------------------------------------------------------------
class LeaseDB:
    OFFER_HOLD = 30          # seconds an offered IP is kept for the client
    DECLINE_HOLD = 3600      # seconds a declined (conflicting) IP is skipped

    def __init__(self, network, first, last, lease_time, reservations, path):
        self.net = network
        self.first, self.last = int(first), int(last)
        self.lease_time = lease_time
        self.reservations = reservations                    # mac -> ip
        self.reserved_ips = {ip: m for m, ip in reservations.items()}
        self.path = path
        self.leases = {}     # mac -> {ip, start, expires, hostname}
        self.offers = {}     # mac -> (ip, expires)
        self.blocked = {}    # ip  -> expires
        self.load()

    # ---- helpers ----
    def in_pool(self, ip):
        try:
            return self.first <= int(ipaddress.IPv4Address(ip)) <= self.last
        except ValueError:
            return False

    def valid_for(self, ip, mac):
        return self.reservations.get(mac) == ip or (
            self.in_pool(ip) and ip not in self.reserved_ips)

    def taken(self, ip, mac):
        """Is `ip` unavailable to `mac`?"""
        if ip in self.blocked:
            return True
        if self.reserved_ips.get(ip, mac) != mac:
            return True
        if any(m != mac and l["ip"] == ip for m, l in self.leases.items()):
            return True
        if any(m != mac and o[0] == ip for m, o in self.offers.items()):
            return True
        return False

    def cleanup(self):
        now = time.time()
        for mac in [m for m, l in self.leases.items() if l["expires"] <= now]:
            log.info("lease expired: %s (%s)", self.leases[mac]["ip"], mac)
            del self.leases[mac]
        self.offers = {m: o for m, o in self.offers.items() if o[1] > now}
        self.blocked = {i: t for i, t in self.blocked.items() if t > now}

    # ---- operations used by the server ----
    def allocate(self, mac, requested=None):
        """DISCOVER: pick an IP to offer."""
        self.cleanup()
        choice = None
        if mac in self.reservations:                       # 1. static reservation
            choice = self.reservations[mac]
        elif mac in self.leases:                           # 2. same IP as before
            choice = self.leases[mac]["ip"]
        elif requested and self.valid_for(requested, mac) \
                and not self.taken(requested, mac):        # 3. what the client asked
            choice = requested
        else:                                              # 4. first free address
            for n in range(self.first, self.last + 1):
                ip = str(ipaddress.IPv4Address(n))
                if ip not in self.reserved_ips and not self.taken(ip, mac):
                    choice = ip
                    break
        if choice:
            self.offers[mac] = (choice, time.time() + self.OFFER_HOLD)
        return choice

    def commit(self, mac, ip, hostname):
        """REQUEST: turn an offer into a real lease (or refuse)."""
        self.cleanup()
        if not self.valid_for(ip, mac) or self.taken(ip, mac):
            return None
        now = time.time()
        lease = {"ip": ip, "start": now, "expires": now + self.lease_time,
                 "hostname": hostname}
        self.leases[mac] = lease
        self.offers.pop(mac, None)
        self.save()
        return lease

    def release(self, mac, ip):
        if self.leases.get(mac, {}).get("ip") == ip:
            del self.leases[mac]
            self.save()
            return True
        return False

    def decline(self, mac, ip):
        self.blocked[ip] = time.time() + self.DECLINE_HOLD
        self.leases.pop(mac, None)
        self.offers.pop(mac, None)
        self.save()

    # ---- persistence ----
    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.leases, f, indent=2)
        os.replace(tmp, self.path)

    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            now = time.time()
            self.leases = {m: l for m, l in data.items() if l["expires"] > now}
            log.info("loaded %d active lease(s) from %s", len(self.leases), self.path)
        except (ValueError, KeyError, OSError) as e:
            log.warning("could not read %s: %s", self.path, e)

    def reservation_table(self):
        if not self.reservations:
            return "  (no reservations - start the server with --reserve MAC=IP)"
        rows = ["  %-17s %-15s %s" % ("MAC", "RESERVED IP", "STATUS")]
        for mac, ip in self.reservations.items():
            l = self.leases.get(mac)
            status = ("leased now (%ds left)" % (l["expires"] - time.time())
                      if l else "not leased right now")
            rows.append("  %-17s %-15s %s" % (mac, ip, status))
        return "\n".join(rows)

    def table(self):
        self.cleanup()
        if not self.leases:
            return "  (no active leases)"
        rows = ["  %-15s %-17s %-8s %s" % ("IP", "MAC", "LEFT(s)", "HOSTNAME")]
        for mac, l in sorted(self.leases.items(), key=lambda x: x[1]["ip"]):
            rows.append("  %-15s %-17s %-8d %s" % (
                l["ip"], mac, l["expires"] - time.time(), l["hostname"]))
        return "\n".join(rows)


# --------------------------------------------------------------------------
# The server itself
# --------------------------------------------------------------------------
class DhcpServer:
    def __init__(self, args, db):
        self.a, self.db = args, db
        net = db.net
        self.server_ip = args.server_ip
        self.config_opts = {                      # options we can hand out
            OPT_SUBNET: ip_to_bytes(str(net.netmask)),
            OPT_ROUTER: ip_to_bytes(args.router),
            OPT_DNS: b"".join(ip_to_bytes(d) for d in args.dns),
            OPT_DOMAIN: args.domain.encode(),
            OPT_BROADCAST: ip_to_bytes(str(net.broadcast_address)),
        }
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if args.iface:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                 args.iface.encode())
        self.sock.bind(("0.0.0.0", args.server_port))

    # ---- building replies ----
    def options_for(self, req, msg_type, with_lease=True):
        opts = [(OPT_MSGTYPE, bytes([msg_type])),
                (OPT_SERVER_ID, ip_to_bytes(self.server_ip))]
        if with_lease:
            lt = self.db.lease_time
            opts += [(OPT_LEASE, struct.pack("!I", lt)),
                     (OPT_T1, struct.pack("!I", lt // 2)),
                     (OPT_T2, struct.pack("!I", lt * 7 // 8))]
        wanted = set(req["options"].get(OPT_PARAM_REQ, b""))
        for code, data in self.config_opts.items():
            if not wanted or code in wanted:       # honour Parameter Request List
                opts.append((code, data))
        return opts

    def reply(self, req, addr, msg_type, yiaddr="0.0.0.0", options=None):
        pkt = build_packet(BOOTREPLY, req["xid"], req["flags"], "0.0.0.0",
                           yiaddr, self.server_ip, req["giaddr"],
                           req["mac"], options)
        # Client already has an address (renewal) or we are in unicast/demo
        # mode -> answer the sender directly. Otherwise broadcast.
        if addr[0] != "0.0.0.0":
            dest = addr
        else:
            dest = ("255.255.255.255", self.a.client_port)
        self.sock.sendto(pkt, dest)
        log.info("-> %-8s to %s:%d  yiaddr=%s", MSG_NAMES[msg_type],
                 dest[0], dest[1], yiaddr)

    # ---- handling requests ----
    def handle(self, data, addr):
        req = parse_packet(data)
        if not req or req["op"] != BOOTREQUEST or req["msg_type"] is None:
            return
        t, mac, o = req["msg_type"], req["mac"], req["options"]
        hostname = o.get(OPT_HOSTNAME, b"").decode(errors="replace")
        log.info("<- %-8s from %s:%d mac=%s host=%s xid=%08x",
                 MSG_NAMES.get(t, t), addr[0], addr[1], mac, hostname or "-", req["xid"])

        if t == DISCOVER:
            wanted = o.get(OPT_REQ_IP)
            want_ip = bytes_to_ip(wanted) if wanted else None
            ip = self.db.allocate(mac, want_ip)
            if ip is None:
                log.warning("address pool exhausted, ignoring DISCOVER from %s", mac)
                return
            if want_ip and ip != want_ip:
                owner = self.db.reserved_ips.get(want_ip)
                why = ("RESERVED for %s" % owner if owner and owner != mac
                       else "not available")
                log.warning("%s asked for %s but it is %s -> offering %s instead",
                            mac, want_ip, why, ip)
            self.reply(req, addr, OFFER, ip, self.options_for(req, OFFER))

        elif t == REQUEST:
            sid = o.get(OPT_SERVER_ID)
            if sid and bytes_to_ip(sid) != self.server_ip:     # client picked another server
                self.db.offers.pop(mac, None)
                log.info("client %s chose server %s, withdrawing offer", mac, bytes_to_ip(sid))
                return
            if OPT_REQ_IP in o:
                ip = bytes_to_ip(o[OPT_REQ_IP])
            elif req["ciaddr"] != "0.0.0.0":                    # renewing
                ip = req["ciaddr"]
            else:
                return
            lease = self.db.commit(mac, ip, hostname)
            if lease:
                log.info("lease granted: %s -> %s for %ds", ip, mac, self.db.lease_time)
                self.reply(req, addr, ACK, ip, self.options_for(req, ACK))
            else:
                nak = [(OPT_MSGTYPE, bytes([NAK])),
                       (OPT_SERVER_ID, ip_to_bytes(self.server_ip)),
                       (OPT_MESSAGE, b"requested address not available")]
                self.reply(req, addr, NAK, "0.0.0.0", nak)

        elif t == RELEASE:
            if self.db.release(mac, req["ciaddr"]):
                log.info("lease released: %s by %s", req["ciaddr"], mac)

        elif t == DECLINE:
            if OPT_REQ_IP in o:
                bad = bytes_to_ip(o[OPT_REQ_IP])
                self.db.decline(mac, bad)
                log.warning("%s declined %s (conflict?) - blocking it for 1h", mac, bad)

        elif t == INFORM:      # client has a static IP, only wants config options
            self.reply(req, addr, ACK, "0.0.0.0",
                       self.options_for(req, ACK, with_lease=False))

    # ---- main loop ----
    def serve(self):
        log.info("DHCP server %s listening on UDP %d (clients reply on %d)",
                 self.server_ip, self.a.server_port, self.a.client_port)
        log.info("pool %s - %s  mask %s  router %s  lease %ds",
                 self.a.pool_start, self.a.pool_end, self.db.net.netmask,
                 self.a.router, self.db.lease_time)
        for mac, ip in self.db.reservations.items():
            log.info("reservation: %s -> %s", mac, ip)
        print("Commands: leases | reservations | quit  (type 'help' to repeat)")
        watch = [self.sock, sys.stdin]
        while True:
            ready, _, _ = select.select(watch, [], [], 1.0)
            for r in ready:
                if r is self.sock:
                    data, addr = self.sock.recvfrom(4096)
                    try:
                        self.handle(data, addr)
                    except Exception:                # never let one bad packet kill us
                        log.exception("error while handling packet from %s", addr)
                else:
                    line = sys.stdin.readline()
                    if line == "":                   # stdin closed (nohup etc.)
                        watch.remove(sys.stdin)
                    elif line.strip() == "leases":
                        print(self.db.table())
                    elif line.strip() == "reservations":
                        print(self.db.reservation_table())
                    elif line.strip() == "help":
                        print("Commands: leases | reservations | quit")
                    elif line.strip() in ("quit", "exit"):
                        return
            self.db.cleanup()


def main():
    p = argparse.ArgumentParser(description="Simple DHCP server (ITT440)")
    p.add_argument("--server-ip", default=None, help="this server's IP (auto-detected)")
    p.add_argument("--network", default="192.168.50.0/24")
    p.add_argument("--pool-start", default=None)
    p.add_argument("--pool-end", default=None)
    p.add_argument("--router", default=None)
    p.add_argument("--dns", nargs="+", default=["8.8.8.8", "1.1.1.1"])
    p.add_argument("--domain", default="itt440.lab")
    p.add_argument("--lease-time", type=int, default=120, help="seconds (short = easy to demo)")
    p.add_argument("--reserve", action="append", default=[], metavar="MAC=IP",
                   help="static reservation, repeatable")
    p.add_argument("--server-port", type=int, default=67)
    p.add_argument("--client-port", type=int, default=68)
    p.add_argument("--iface", default=None, help="bind to one interface (needs root)")
    p.add_argument("--lease-file", default="leases.json")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args()

    net = ipaddress.ip_network(a.network, strict=False)
    hosts = list(net.hosts())
    a.pool_start = a.pool_start or str(hosts[99] if len(hosts) > 100 else hosts[0])
    a.pool_end = a.pool_end or str(hosts[149] if len(hosts) > 150 else hosts[-1])
    a.router = a.router or str(hosts[0])
    if a.server_ip is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))        # no packet is actually sent
            a.server_ip = s.getsockname()[0]
        except OSError:
            a.server_ip = "127.0.0.1"
        finally:
            s.close()

    reservations = {}
    for item in a.reserve:
        mac, ip = item.split("=")
        reservations[mac.lower().replace("-", ":")] = ip

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    db = LeaseDB(net, ipaddress.IPv4Address(a.pool_start), ipaddress.IPv4Address(a.pool_end),
                 a.lease_time, reservations, a.lease_file)
    try:
        server = DhcpServer(a, db)
    except PermissionError:
        sys.exit("Permission denied: ports below 1024 need root. Use sudo, "
                 "or --server-port 6767 --client-port 6868.")
    except OSError as e:
        sys.exit(f"Cannot bind UDP {a.server_port}: {e}")
    try:
        server.serve()
    except KeyboardInterrupt:
        pass
    print("\nFinal leases:\n" + db.table())
    db.save()


if __name__ == "__main__":
    main()
