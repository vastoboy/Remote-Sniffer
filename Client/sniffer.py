import json
import time
import queue
import socket
import textwrap
import threading
from protocols import Protocols
from datetime import datetime


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '



class SimpleSniffer:

    def __init__(self, sock):
        self.protocols = Protocols()
        self.sock = sock
        self.now = datetime.now()
        self.capture_queue = queue.Queue()  # Initialize the queue


    # Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
    def get_mac_addr(self, mac_raw):
        byte_str = map('{:02x}'.format, mac_raw)
        mac_addr = ':'.join(byte_str).upper()
        return mac_addr



    # Formats multi-line data
    def format_multi_line(self, prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



    def process_captures(self):
        while True:
            # Directly check if the queue size equals 100
            if self.capture_queue.qsize() >= 100:
                captures = []  # Temporary list to store captures for processing
                
                # Since we're checking the queue's size, we now need to dequeue exactly 100 items
                for _ in range(100):
                    if not self.capture_queue.empty():
                        capture = self.capture_queue.get()  # Get a capture from the queue
                        captures.append(capture)  # Append it to the temporary list
                
                # Process (in this case, print) the captures
                print(captures)
                # No need to reset the captures list here since it's created fresh each time the condition is met



    def main(self):
        
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while True:
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

            print('\nEthernet Frame:')
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth_dest_mac, eth_src_mac, eth_proto))

            # IPv4
            if eth_proto == 8:
                ipv4_version_header_length, ipv4_version, ipv4_header_length, ipv4_ttl, ipv4_proto, ipv4_src, ipv4_target, ipv4_data = self.protocols.ipv4(eth_data)
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4_version, ipv4_header_length, ipv4_ttl))
                print(TAB_2 + 'Protocol: {}, Source: {}, Destination: {}'.format(ipv4_proto, ipv4_src, ipv4_target))

                capture.update({
                           "IPV4 Version Header Length": ipv4_version_header_length, 
                           "IPV4 Version": ipv4_version, 
                           "IPV4 Header Length": ipv4_header_length, 
                           "IPV4 TTL": ipv4_ttl, 
                           "IPV4 Proto": ipv4_proto, 
                           "IPV4 Source": ipv4_src, 
                           "IPV4 Target": ipv4_target, 
                           "IPV4 data": ipv4_data.hex()
                           })


                # ICMP
                if ipv4_proto == 1:
                    icmp_packet_type, icmp_code, icmp_checksum, icmp_data = self.protocols.icmp(ipv4_data)
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_packet_type, icmp_code, icmp_checksum))
                    print(TAB_2 + 'ICMP Data:')
                    print(self.format_multi_line(DATA_TAB_3, icmp_data))

                    capture.update({ 
                                "Icmp Packet Type": icmp_packet_type, 
                                "Icmp Code": icmp_code, 
                                "Icmp Checksum": icmp_checksum, 
                                "Icmp Data": icmp_data.hex()
                                })


                # TCP
                elif ipv4_proto == 6:
                    tcp_src_port, tcp_dest_port, tcp_sequence, tcp_acknowledgment, tcp_offset, tcp_flag_urg, tcp_flag_ack, tcp_flag_psh, tcp_flag_rst, tcp_flag_syn, tcp_flag_fin, tcp_data = self.protocols.tcp(ipv4_data)
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp_src_port, tcp_dest_port))
                    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp_sequence, tcp_acknowledgment))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp_flag_urg, tcp_flag_ack, tcp_flag_psh))
                    print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp_flag_rst, tcp_flag_syn, tcp_flag_fin))


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
                            print(TAB_2 + 'HTTP Data:')
                            try:
                                http_data = self.protocols.http(tcp_data)
                                capture.update({"HTTP Data": http_data.hex()})

                                http_info = str(http_data).split('\n')
                                for line in http_info:
                                    print(DATA_TAB_3 + str(line))
                            except:
                                print(self.format_multi_line(DATA_TAB_3, tcp_data))
                        else:
                            capture.update({"TCP Data": tcp_data.hex()})

                            print(TAB_2 + 'TCP Data:')
                            print(self.format_multi_line(DATA_TAB_3, tcp_data))




                # UDP
                elif ipv4_proto == 17:
                    udp_src_port, udp_dest_port, udp_size, udp_data = self.protocols.udp(ipv4_data)
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp_src_port, udp_dest_port, udp_size))

                    capture.update({
                                "UDP Source Port": udp_src_port, 
                                "UDP Destination Port": udp_dest_port, 
                                "UDP Size": udp_size, 
                                "UDP Data": udp_data.hex()
                                })



                # Other IPv4
                else:
                    print(TAB_1 + 'Other IPv4 Data:')
                    print(self.format_multi_line(DATA_TAB_2, ipv4_data))

                    capture.update({"Other IPV4 Data": ipv4_data.hex()})


            else:
                print('Ethernet Data:')
                print(self.format_multi_line(DATA_TAB_1, eth_data))

                capture.update({"Ethernet Data": eth_data.hex()})


            self.capture_queue.put(capture)
            print("The length of the queue is======================================:", self.capture_queue.qsize())




