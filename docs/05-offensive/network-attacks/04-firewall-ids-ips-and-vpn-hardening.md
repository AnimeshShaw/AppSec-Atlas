---
title: 04 - Firewall, IDS/IPS, & VPN Hardening
description: Suricata is a high-performance Network IDS, IPS, and Network Security
  Monitoring engine.
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '05'
- Offensive
- Network
- Attacks
- '04'
- Firewall
- Ids
- Ips
- And
- Vpn
- Hardening
- Md
slug: /offensive/network-attacks/firewall-ids-ips-and-vpn-hardening
---


# 04 - Firewall, IDS/IPS, & VPN Hardening

## Stateful Firewalls vs WAFs
- **Stateful Firewalls (Layer 3/4):** Track active connections and state (e.g., SYN, ESTABLISHED). Good for blocking IPs and ports, but blind to application payloads.
- **Web Application Firewalls (Layer 7):** Inspect HTTP/S traffic for SQLi, XSS, and application-specific anomalies.

## Suricata IDS/IPS Rules
Suricata is a high-performance Network IDS, IPS, and Network Security Monitoring engine.

### Suricata Rule Syntax
```suricata
# Alert on plaintext HTTP credentials
alert http `$HOME_NET any -> $`EXTERNAL_NET any (msg:"Cleartext password transmitted"; content:"password="; nocase; classtype:policy-violation; sid:100001; rev:1;)

# IPS Inline Blocking for known malicious IP
drop ip 198.51.100.0/24 any -> $HOME_NET any (msg:"Drop traffic from bad subnet"; sid:100002; rev:1;)
```

## VPN Hardening: WireGuard & IPsec
VPNs encrypt traffic between sites or remote workers. 

### WireGuard Hardening
WireGuard uses state-of-the-art cryptography (ChaCha20, Poly1305, Curve25519) and is much simpler than IPsec.

**Server Config (wg0.conf):**
```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY>
# Strict firewall rules
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <CLIENT_PUBLIC_KEY>
# Pre-shared key adds quantum resistance
PresharedKey = <PRE_SHARED_KEY>
AllowedIPs = 10.0.0.2/32
```
