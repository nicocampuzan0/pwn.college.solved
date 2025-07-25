# Problem Statement

## Observations
- The tricky part here is exfiltrating the chosen plaintext, bruteforcing is trivial like in the first CPA challenge.
  - To achieve this, we can use the `substr` SQL function so we can still guess character by character and not worry about the 16B padding for AES throwing us off since we match the input length.
- However, when interacting directly with the process that encrypts/decrypts like before, efficiency didn't really matter, now we are doing this through a web server.
  - We can speed things up by using a subset of the printable ASCII characters (note, skip `#` for these queries...) to reduce the search space to 82 characters.
  - We can also build a lookup table for our flag substring queries, since these don't change and we would be making on average 41 queries for the encrypted flag substring, when we only need 1.
    - Using a dictionary might have been more pythonic, but when I set up the problem I was thinking a table might be faster for a small range of contiguous integers, which made my logic a bit hacky and ugly
- Also note that the known `pwn.college{` prefix is irrelevant. It's just the first step in knowing I can choose plaintext to encrypt and match the flag ciphertext as below that I left in there. We could start from indrex 13 instea:
  - ```
    # python -c "import requests; print(requests.get('http://challenge.localhost/?query=substr(flag, 1, 12)').text)"
    #DEBUG: sql='SELECT substr(flag, 1, 12) FROM secrets'
    #127.0.0.1 - - [25/Jul/2025 02:00:55] "GET /?query=substr(flag,%201,%2012) HTTP/1.1" 200 -
    
    #        <html><body>Welcome to pwn.secret!
    #        <form>SELECT <input type=text name=query value='substr(flag, 1, 12)'> FROM secrets<br><input type=submit value=Submit></form>
    #        <hr>
    #        <b>Query:</b> <pre>SELECT substr(flag, 1, 12) FROM secrets</pre><br>
    #        <b>Results:</b><pre>e382562c7be43524d6d91906a940e5ce</pre>
    #        </body></html>
    ```
  - ```
    #python -c "import requests; print(requests.get('http://challenge.localhost/?query=\'pwn.college{\'').text)"
    #DEBUG: sql="SELECT 'pwn.college{' FROM secrets"
    #127.0.0.1 - - [25/Jul/2025 02:03:37] "GET /?query='pwn.college{' HTTP/1.1" 200 -
  
    #        <html><body>Welcome to pwn.secret!
    #        <form>SELECT <input type=text name=query value=''pwn.college{''> FROM secrets<br><input type=submit value=Submit></form>
    #        <hr>
    #        <b>Query:</b> <pre>SELECT 'pwn.college{' FROM secrets</pre><br>
    #        <b>Results:</b><pre>e382562c7be43524d6d91906a940e5ce</pre>
    #        </body></html>
    ```
## Solution
```
from pwn import *
import requests

p = process("/challenge/run")

flag = "pwn.college{"
start = 45 # beginning of printable ASCII chars except the first 12 chars I know aren't in flags
end = 126 # end of printable ASCII chars
ct_table = [None] * 13 # create indexes 0 through 12 - since we already know the prefix  `pwn.college{`
length_index = 12 # we start at length index 13, but increment first thing in the loop below

while flag[-1:] != '}':
    length_index += 1
    for char in range(start, end+1):
        # Generate our chosen ciphertext with what we know so far + a guess at the next printable char
        guess = requests.get(f"http://challenge.localhost/?query='{flag + chr(char)}'")
        guess = guess.text.split("<b>Results:</b><pre>")[1].split("</pre>")[0]
       
        # Retrieve the actual ciphertext we are interested in with the base we know + next char
        # Only do this step once and build a lookup table for efficiency, since output won't change
        if(len(flag) == len(ct_table) - 1):
            ct = requests.get(f"http://challenge.localhost/?query=substr(flag, 1, {length_index})")
            ct = ct.text.split("<b>Results:</b><pre>")[1].split("</pre>")[0]
            ct_table.append(ct)
        
        # Append correctly guessed char to flag or keep trying with next char
        if guess == ct_table[length_index]:
            flag += chr(char)
            break

print(flag)
```
