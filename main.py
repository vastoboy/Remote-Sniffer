import socket
from protocols import Protocols
from pcap import Pcap
import textwrap



TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


protocols = Protocols()


# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



def main():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth_dest_mac, eth_src_mac, eth_proto, eth_data = protocols.ethernet(raw_data)

        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth_dest_mac, eth_src_mac, eth_proto))

        # IPv4
        if eth_proto == 8:
            ipv4_version_header_length, ipv4_version, ipv4_header_length, ipv4_ttl, ipv4_proto, ipv4_src, ipv4_target, ipv4_data = protocols.ipv4(eth_data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4_version, ipv4_header_length, ipv4_ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4_proto, ipv4_src, ipv4_target))

            # ICMP
            if ipv4_proto == 1:
                icmp_packet_type, icmp_code, icmp_checksum, icmp_data = protocols.icmp(ipv4_data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_packet_type, icmp_code, icmp_checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp_data))

            # TCP
            elif ipv4_proto == 6:
                tcp_src_port, tcp_dest_port, tcp_sequence, tcp_acknowledgment, tcp_offset, tcp_flag_urg, tcp_flag_ack, tcp_flag_psh, tcp_flag_rst, tcp_flag_syn, tcp_flag_fin, tcp_data = protocols.tcp(ipv4_data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp_src_port, tcp_dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp_sequence, tcp_acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp_flag_urg, tcp_flag_ack, tcp_flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp_flag_rst, tcp_flag_syn, tcp_flag_fin))

                if len(tcp_data) > 0:

                    # HTTP
                    if tcp_src_port == 80 or tcp_dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp_data)
                            http_info = str(http_data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp_data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp_data))

            # UDP
            elif ipv4_proto == 17:
                udp_src_port, udp_dest_port, udp_size, udp_data = protocols.udp(ipv4_data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp_src_port, udp_dest_port, udp_size))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4_data))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth_data))

    pcap.close()



main()