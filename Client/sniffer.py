import json
import time
import queue
import socket
import textwrap
import threading
from datetime import datetime
from protocols import Protocols




class SimpleSniffer:

    def __init__(self, server_ip):
        self.protocols = Protocols()
        self.now = datetime.now()
        self.capture_queue = queue.Queue()  # Initialize the queue
        self.server_ip = server_ip
        self._stop_thread = threading.Event()



    def stop_thread(self):
        self._stop_thread.set()



    def resume(self):
        self._stop_thread.clear()



    def process_captures(self, sock):
            while not self._stop_thread.is_set():
                try:
                    if self.capture_queue.qsize() >= 100: 
                        captures = []  # Temporary list to store captures for processing
                        for _ in range(100):
                            if not self.capture_queue.empty():
                                capture = self.capture_queue.get()  # Get a capture from the queue
                                print(capture)
                                captures.append(capture)  
                        
                        captures_json = json.dumps(captures)
                        captures_bytes = captures_json.encode()
                        
                        sock.sendall(captures_bytes)
                        self.capture_queue.task_done() # Ensure items are removed from the queue after processing

                except BrokenPipeError as e: #stop sending if connection is no longer active
                    print(f"Broken pipe error occurred: {e}")
                    break



    def main(self):
        
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while not self._stop_thread.is_set():
            capture = {}
            raw_data, addr = conn.recvfrom(65535)
            eth_dest_mac, eth_src_mac, eth_proto, eth_data = self.protocols.ethernet(raw_data)

            capture = {
                        "Date": str(self.now.date()),
                        "Time": str(self.now.time()),
                        "Ethernet Destination Mac": eth_dest_mac, 
                        "Ethernet Source Mac": eth_src_mac, 
                        "Ethernet Proto": eth_proto
                        }


            # IPv4
            if eth_proto == 8:
                ipv4_version_header_length, ipv4_version, ipv4_header_length, ipv4_ttl, ipv4_proto, ipv4_src, ipv4_dst, ipv4_data = self.protocols.ipv4(eth_data)

                if ipv4_dst == self.server_ip:
                    # Do not collect data being sent back to the server
                    print("Dest-IP------------------------------------------------------------------------------------->")


                else:
                    capture.update({
                               "IPV4 Version Header Length": ipv4_version_header_length, 
                               "IPV4 Version": ipv4_version, 
                               "IPV4 Header Length": ipv4_header_length, 
                               "IPV4 TTL": ipv4_ttl, 
                               "IPV4 Proto": ipv4_proto, 
                               "IPV4 Source": ipv4_src, 
                               "IPV4 Target": ipv4_dst, 
                               "IPV4 Data": str(ipv4_data)
                               })


                    # ICMP
                    if ipv4_proto == 1:
                        icmp_packet_type, icmp_code, icmp_checksum, icmp_data = self.protocols.icmp(ipv4_data)
                        capture.update({ 
                                    "Icmp Packet Type": icmp_packet_type, 
                                    "Icmp Code": icmp_code, 
                                    "Icmp Checksum": icmp_checksum, 
                                    "Icmp Data": str(icmp_data)
                                    })


                    # TCP
                    elif ipv4_proto == 6:
                        tcp_src_port, tcp_dest_port, tcp_sequence, tcp_acknowledgment, tcp_offset, tcp_flag_urg, tcp_flag_ack, tcp_flag_psh, tcp_flag_rst, tcp_flag_syn, tcp_flag_fin, tcp_data = self.protocols.tcp(ipv4_data)
                        capture.update({ 
                                    "TCP Source Port": tcp_src_port, 
                                    "TCP Destination Port": tcp_dest_port, 
                                    "TCP Sequence": tcp_sequence, 
                                    "TCP Acknowledgement": tcp_acknowledgment, 
                                    "TCP Offset": tcp_offset, 
                                    "TCP Flag URG": tcp_flag_urg, 
                                    "TCP Flag ACK": tcp_flag_ack, 
                                    "TCP Flag PSH": tcp_flag_psh, 
                                    "TCP Flag RST": tcp_flag_rst, 
                                    "TCP Flag SYN": tcp_flag_syn, 
                                    "TCP Flag FIN": tcp_flag_fin
                                    })
                        

                        if len(tcp_data) > 0:

                            # HTTP
                            if tcp_src_port == 80 or tcp_dest_port == 80:
                                try:
                                    http_data = self.protocols.http(tcp_data)
                                    capture.update({"HTTP Data": str(http_data)})
                                except:
                                    continue
                            else:
                                capture.update({"TCP Data": str(tcp_data)})



                    # UDP
                    elif ipv4_proto == 17:
                        udp_src_port, udp_dest_port, udp_size, udp_data = self.protocols.udp(ipv4_data)
                        capture.update({
                                    "UDP Source Port": udp_src_port, 
                                    "UDP Destination Port": udp_dest_port, 
                                    "UDP Size": udp_size, 
                                    "UDP Data": str(udp_data)
                                    })

                    # Other IPv4
                    else:
                        capture.update({"Other IPV4 Data": str(ipv4_data)})


            else:
                capture.update({"Ethernet Data": str(eth_data)})


            self.capture_queue.put(capture)
            print("The length of the queue is========================================================:", self.capture_queue.qsize())

