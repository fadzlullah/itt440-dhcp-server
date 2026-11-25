# ITT440 - DHCP Server & Client (Python)

Server: Linux (WSL on Windows). Client: Windows cmd. No VMware.

Files: `dhcp_common.py` (packet build/parse), `dhcp_server.py`, `dhcp_client.py`

## Run (demo mode, no sudo, safe for any network)
WSL terminal:
    hostname -I                      # note the first IP, e.g. 172.20.10.5
    python3 dhcp_server.py --server-port 6767 --client-port 6868 -v

Windows cmd (same folder, all 3 files):
    python dhcp_client.py --server 172.20.10.5 --server-port 6767 --client-port 6868

## Extra options
    --lease-time 30                      short lease to demo expiry/renewal
    --reserve 02:00:00:00:00:99=192.168.50.10   static reservation
    --mac 02:00:00:00:00:02              pretend to be a second client
Server console: type `leases` or `quit`.

## References
RFC 2131 (DHCP), RFC 2132 (DHCP options), RFC 951 (BOOTP)
