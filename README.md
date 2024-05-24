# COSC 60 Lab 3 - Julian George

## File Structure

- **tcp_responder.py**: submission for task 1
- **tcp_responder.py**: submission for task 2a
- **tcp6_responder.py**: submission for task 2b
- requirements.txt: required python packages
- http-jpg-response.txt: tcp payload for tcp_responder
- hello.txt: short, single-packet tcp payload for use with netcat -l
- lipsum.txt: long, multi-packet tcp payload for use with netcat -l
- output.txt: after running tcp_responder.py, resulting payload will be saved here
- output_v6.txt: after running tcp6_responder.py, resulting paylaod will be saved here

## Acknowledgements

I used ChatGPT to get an initial solution to each of these, but this time I ended up rewriting most of what they gave me. Also used it to generate much of tcp6_connector based on what I made for tcp_connector.

## Setup

Setup a python venv first by running `python3 -m venv venv; source venv/bin/activate;`, then `pip3 install -r requirements.txt` (I will have done this already in the pond). Further python scripts should be run in the venv

## Task 1

Tested by accessing the printed IP in the browser. Ran the iptables packet loss commands to simulate packet loss. On cmd line, ran `nc <ip_address> 8080 > responder_output.txt`

## Task 2a

Tested by running `nc -l 8888 < lipsum.txt` (I had this directory mounted on two different multipass instances). Then ran `tcp_connector.py <ip_address> 8888` and checked output.txt.

## Task 2b

Similarly, after altering the IPv6 addresses as suggested, I tested by running `nc -6 -l 8888 < lipsum.txt`. Then ran `tcp6_connector.py <ipv6_address> 8888` and checked output.txt.

## Other notes

Used Wireshark extensively to make sure packet behavior was as desired. My programs exit out immediately after getting an RST flag, and my connectors begin the FIN sequence after timing out for the next packet frame.
