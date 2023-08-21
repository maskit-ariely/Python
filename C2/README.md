
# Command & Control (C2)

This project is an implementation of Command & Control (C2) channel that utilizes the Internet Control Message Protocol (ICMP) to covertly manage a single compromised host. 
## Features

- Remote Command Execution: Execute commands on the agents's machine and receive the results covertly.
- File Transfer Capability: Transfer files from the agent.
- Heartbeat Mechanism: Continuous "hey server, I'm available" message ensures agents's availability is constantly checked.


## Requirements
- Linux-based systems
- scapy library on the server machine (`sudo apt-get install python3-scapy`)
- Root access (some operations require superuser privileges)
## Before Getting Started
- Make sure you have scapy library installed
- There's a dedicated configuration file for the server, ensure you fill in the parameters correctly
- Update the SERVER_IP constant in the agent code to the server's IP address
## Execution and Usage

1. Clone or download the repository to your local machine.
2. Open a terminal and navigate to the directory containing the downloaded files.
3. Execute the programs with the following commands:
```bash
sudo python3 server.py
```
```bash
sudo python3 agent.py
```
4. Enter commands like `send <filename>` or `run <command>` in the server's terminal.
## Demo
[![Watch the video](https://i.ytimg.com/vi/gYFdk05Q24g/maxresdefault.jpg)](https://youtu.be/gYFdk05Q24g)