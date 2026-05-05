# audit-egress-proxy deployment

This service routes credential-audit Pass-2 logins through a WireGuard tunnel
to a sacrificial public exit IP. **Vault-proxy itself continues to use the
home IP for everything else** (vault unlock, weak/reuse audit, rotation).

The container runs `qmcgaw/gluetun` configured as a custom WireGuard client.
It exposes an HTTP CONNECT proxy on port `8888` bound to the homelab LAN IP
`10.0.0.207`. Vault-proxy on the dev box reaches it as
`http://10.0.0.207:8888`.

## Topology

```
dev-box (vault-proxy binary, Pass-2 driver)
        |
        | HTTP CONNECT
        v
homelab:8888  ─►  audit-egress-proxy (gluetun)
                              |
                              | WireGuard tunnel
                              v
                  OPNsense WG server
                              |
                              | sacrificial WAN egress
                              v
                       target login site
```

## Operator setup — one-time

### 1. OPNsense: configure WireGuard server + peer

In OPNsense → **VPN → WireGuard**:

1. **Local (Server)** instance: pick a port (e.g. `51820`), generate a server
   keypair, assign tunnel subnet (e.g. `10.64.222.0/24`).
2. **Endpoint (Peer)** for the audit proxy:
   - Generate a peer keypair (note the **peer private key** and **peer public key**)
   - Allowed IPs: `10.64.222.21/32` (or whatever you assign the peer)
   - Pre-shared key: optional but recommended; generate one
3. **Outbound NAT** (Firewall → NAT → Outbound):
   - Add a manual rule that NATs traffic from the WG tunnel subnet
     (`10.64.222.0/24`) to the **sacrificial WAN** interface, not the primary
     WAN. The whole point of this proxy is that login attempts exit on a
     burnable IP that won't pollute the home WAN's reputation.
4. **Firewall rule** on the WG interface allowing outbound to `0.0.0.0/0` for
   the peer.
5. **Port-forward** the WG listen port from the **sacrificial WAN** in to the
   OPNsense WG server (or use OPNsense's WAN interface directly if WG is
   bound there).

You will need these values from OPNsense to populate `wg.env`:

| OPNsense field | gluetun env var |
|---|---|
| Peer private key | `WIREGUARD_PRIVATE_KEY` |
| Server public key | `WIREGUARD_PUBLIC_KEY` |
| Pre-shared key (if used) | `WIREGUARD_PRESHARED_KEY` |
| Public IP of sacrificial WAN | `WIREGUARD_ENDPOINT_IP` |
| Listen port | `WIREGUARD_ENDPOINT_PORT` |
| Peer tunnel address | `WIREGUARD_ADDRESSES` (e.g. `10.64.222.21/32`) |

### 2. Homelab: drop wg.env

Create `deploy/audit-egress-config/wg.env` on the homelab with the values from
the table above. Example:

```env
WIREGUARD_PRIVATE_KEY=wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=
WIREGUARD_PUBLIC_KEY=wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=
WIREGUARD_PRESHARED_KEY=xOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=
WIREGUARD_ENDPOINT_IP=203.0.113.42
WIREGUARD_ENDPOINT_PORT=51820
WIREGUARD_ADDRESSES=10.64.222.21/32
```

Permissions: `chmod 600 deploy/audit-egress-config/wg.env`. Do not commit.

### 3. Bring the proxy up

```bash
cd ~/projects/Connecterr/vault-proxy
docker compose -f deploy/docker-compose.audit-egress.yml up -d
```

### 4. Verify the exit IP

```bash
# Direct from inside the container — should show the sacrificial WAN IP:
sudo docker exec audit-egress-proxy wget -qO- https://api.ipify.org
echo

# From the dev box, through the HTTP proxy — same answer:
curl -x http://10.0.0.207:8888 -sS https://api.ipify.org
echo
```

If both show the sacrificial WAN's public IP and not the home WAN, you're
good.

### 5. Restrict access at the OS firewall

The proxy listens on `10.0.0.207:8888`. Restrict to the dev-box IP:

```bash
sudo ufw allow from <dev-box-ip> to any port 8888 proto tcp
sudo ufw deny 8888/tcp
```

### 6. Wire vault-proxy

Set on the dev box (where vault-proxy runs):

```bash
export AUDIT_EGRESS_PROXY_URL=http://10.0.0.207:8888
```

The orchestrator forwards this to Pass-2; Pass-2's Playwright driver
respects it for outbound HTTP/S.

## Failure modes

- Proxy unreachable at start: vault-proxy refuses to start Pass 2 (returns error).
- Proxy goes down mid-run: run pauses with status `paused_proxy_down`.
- Proxy returns non-2xx for HTTP CONNECT: individual item marked `untestable`
  with reason `proxy_connect_failed`.
- WireGuard handshake fails inside gluetun: container restarts; healthcheck
  goes unhealthy; vault-proxy treats as proxy-down.

## Why a separate exit IP?

Vault-proxy makes legitimate connections from the home IP for credential
rotation and (existing) weak/reuse audits. Pass-2 login attempts may trigger
rate limiting, captcha, or short-term IP blocks at the target sites. Sending
those attempts from a sacrificial IP keeps the home IP clean for the
everything-else workloads.
