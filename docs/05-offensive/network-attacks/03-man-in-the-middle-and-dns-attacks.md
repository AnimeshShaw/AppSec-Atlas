---
title: "03 - Man-in-the-Middle & DNS Attacks"
description: "MitM attacks occur when an attacker intercepts communications between two parties. ARP spoofing, rogue access points, and DNS poisoning are common vec..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Network Attacks", "03 Man In The Middle And Dns Attacks.Md"]
---

# 03 - Man-in-the-Middle & DNS Attacks

## Man-in-the-Middle (MitM) Attacks
MitM attacks occur when an attacker intercepts communications between two parties. ARP spoofing, rogue access points, and DNS poisoning are common vectors. The goal is to sniff credentials, inject malicious payloads, or modify data in transit.

## DNS Spoofing & Cache Poisoning
DNS operates largely over unencrypted UDP. Attackers can race to respond to a DNS query faster than the legitimate server, tricking the client or the recursive resolver into caching a malicious IP for a domain.

## SSL/TLS Interception Mechanics
When an attacker is in a MitM position, they can attempt SSL Stripping (forcing HTTP instead of HTTPS) or present a fake certificate. If the client ignores certificate warnings or the attacker compromises a trusted CA, the encryption is defeated.

## HSTS & DNSSEC Defenses
### HTTP Strict Transport Security (HSTS)
HSTS forces browsers to connect via HTTPS, preventing SSL Stripping.
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### DNSSEC
DNSSEC adds cryptographic signatures to DNS records, ensuring their integrity and authenticity, preventing cache poisoning.

#### Working BIND9 DNSSEC Configuration
```bash
# Generate Keys
dnssec-keygen -a ECDSAP256SHA256 -b 256 -n ZONE example.com
dnssec-keygen -f KSK -a ECDSAP256SHA256 -b 256 -n ZONE example.com

# Sign the Zone
dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16) -N INCREMENT -o example.com -t example.com.zone
```
In `named.conf.options`:
```conf
options {
    dnssec-validation auto;
    # enable signing
    dnssec-enable yes;
};
```
