#!/usr/bin/env python3
import socket
import threading
import logging
from loguru import logger
from scapy.all import sniff, IP, TCP, UDP
import json
from datetime import datetime
import os

# Configure logging
logger.add("honeypot.log", rotation="1 MB", level="INFO", format="{time} | {level} | {message}")

class Honeypot:
    def __init__(self, host='<YOUR-MACHINE-IP>', ports=[80, 21, 22, 23, 445, 3389]):
        self.host = host
        self.ports = ports
        self.services = {
            80: self.http_service,
            21: self.ftp_service,
            22: self.ssh_service,
            23: self.telnet_service,
            445: self.smb_service,
            3389: self.rdp_service
        }
        self.attacks = []
        
    def log_attack(self, src_ip, dst_port, payload, attack_type):
        attack = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_port': dst_port,
            'payload': payload[:200],  # Truncate long payloads
            'attack_type': attack_type
        }
        self.attacks.append(attack)
        logger.warning(f"ATTACK DETECTED: {src_ip}:{attack_type} -> port {dst_port}")
        self.save_attacks()
    
    def save_attacks(self):
        with open('attacks.json', 'w') as f:
            json.dump(self.attacks, f, indent=2)

    def generic_service(self, conn, addr, port):
        """Default slow response service"""
        logger.info(f"Connection from {addr[0]} to port {port}")
        try:
            conn.recv(1024)  # Receive banner grab
            conn.send(b"Service running...\r\n")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                logger.info(f"[{addr[0]}:{addr[1]}] -> {data.decode(errors='ignore')[:100]}")
                # Detect common attacks
                payload = data.decode(errors='ignore').lower()
                if any(x in payload for x in ['union', 'select', 'script', 'exec', '/bin/', 'nc -e']):
                    self.log_attack(addr[0], port, data.decode(errors='ignore'), "EXPLOIT_ATTEMPT")
                elif len(data) > 1000:
                    self.log_attack(addr[0], port, data.decode(errors='ignore'), "BUFFER_OVERFLOW")
                conn.send(b"OK\r\n")
        except:
            pass
        finally:
            conn.close()

    def http_service(self, conn, addr):
        self.generic_service(conn, addr, 80)
    
    def ftp_service(self, conn, addr):
        conn.send(b"220 Fake FTP Server\r\n")
        self.generic_service(conn, addr, 21)
    
    def ssh_service(self, conn, addr):
        conn.send(b"SSH-2.0-FakeSSH\r\n")
        self.generic_service(conn, addr, 22)
    
    def telnet_service(self, conn, addr):
        self.generic_service(conn, addr, 23)
    
    def smb_service(self, conn, addr):
        conn.send(b"\x81\x00\x00\x49\x00\x00\x00\x00\x00\x00\x00\x00")  # Fake SMB header
        self.generic_service(conn, addr, 445)
    
    def rdp_service(self, conn, addr):
        self.generic_service(conn, addr, 3389)

    def handle_connection(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, port))
        sock.listen(5)
        logger.info(f"Listening on port {port}")
        
        while True:
            try:
                conn, addr = sock.accept()
                service = self.services.get(port, self.generic_service)
                threading.Thread(target=service, args=(conn, addr)).start()
            except Exception as e:
                logger.error(f"Port {port} error: {e}")

    def packet_sniffer(self):
        """Sniff network traffic for additional intel"""
        def packet_callback(pkt):
            if IP in pkt and TCP in pkt:
                logger.info(f"SCAN: {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
                if pkt[TCP].dport in self.ports and len(pkt[TCP].payload) > 0:
                    self.log_attack(pkt[IP].src, pkt[TCP].dport, str(pkt[TCP].payload), "NETWORK_SCAN")
        
        sniff(prn=packet_callback, filter="tcp or udp", store=0)

    def start(self):
        # Start services
        service_threads = []
        for port in self.ports:
            t = threading.Thread(target=self.handle_connection, args=(port,))
            t.daemon = True
            t.start()
            service_threads.append(t)
        
        # Start packet sniffer
        sniffer_thread = threading.Thread(target=self.packet_sniffer)
        sniffer_thread.daemon = True
        sniffer_thread.start()
        
        logger.info("Honeypot started! Press Ctrl+C to stop.")
        try:
            while True:
                pass
        except KeyboardInterrupt:
            logger.info("Shutting down...")

if __name__ == "__main__":
    hp = Honeypot()
    hp.start()
