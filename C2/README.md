
# Command & Control (C2)

This project is an implementation of Command & Control (C2) channel that utilizes the Internet Control Message Protocol (ICMP) to covertly manage a single compromised host. 
## Features

- Remote Command Execution: Execute commands on the victim's machine and receive the results covertly.
- File Transfer Capability: Transfer files from the victim.
- Heartbeat Mechanism: Continuous "hey server, I'm available" message ensures client's availability is constantly checked.


## Requirements
- Linux-based systems
- scapy library on the server machine (`sudo apt-get install python3-scapy`)
- Root access (some operations require superuser privileges)
## Before Getting Started
- Make sure you have scapy library installed
- There's a dedicated configuration file for the server, ensure you fill in the parameters correctly
- Update the SERVER_IP constant in the Victim code to the server's IP address
## Execution and Usage

1. Clone or download the repository to your local machine.
2. Open a terminal and navigate to the directory containing the downloaded files.
3. Execute the programs with the following commands:
```bash
sudo python3 server.py
```
```bash
sudo python3 victim.py
```
4. Enter commands like `send <filename>` or `run <command>` in the server's terminal.
## Demo
[![Watch the video](https://i.ytimg.com/vi/gYFdk05Q24g/maxresdefault.jpg)](https://youtu.be/gYFdk05Q24g)