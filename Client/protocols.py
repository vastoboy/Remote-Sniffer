import socket
import struct

 
 # https://docs.python.org/3/library/struct.html for a better understanding of struct 
# https://datatracker.ietf.org/doc/html/rfc791#page-11 learn more about internet protocol

class Protocols:

	
	# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
	def get_mac_addr(self, mac_bytes):
		return ':'.join(f'{byte:02X}' for byte in mac_bytes)


	def ipv4(self, raw_data):
		version_header_length = raw_data[0]
		version = version_header_length >> 4
		header_length = (version_header_length & 15) * 4
		ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
		src = self.ipv4_join(src)
		target = self.ipv4_join(target)
		data = raw_data[header_length:]
		return version_header_length, version, header_length, ttl, proto, src, target, data


	# Returns properly formatted IPv4 address
	def ipv4_join(self, addr):
	    return '.'.join(map(str, addr))


	# parse raw tcp packet
	def tcp(self, raw_data):
		(src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])

		# Extract individual TCP flags

		# Calculate the offset to determine the start of TCP payload
		# Bit shift offset_reserved_flags by 12. The value is a 32-bit words 
		# Multiply by 4 to represent length in bytes
		offset = (offset_reserved_flags >> 12) * 4

		# AND offset_reserved_flags by 32 (0000000000100000) and bit shift the result 5 bits (0000000000000001) if the AND operation is 0 it will look like this 0000000000000000 signifying the flag isn't present
		flag_urg = (offset_reserved_flags & 32) >> 5 
		flag_ack = (offset_reserved_flags & 16) >> 4
		flag_psh = (offset_reserved_flags & 8) >> 3
		flag_rst = (offset_reserved_flags & 4) >> 2
		flag_syn = (offset_reserved_flags & 2) >> 1
		flag_fin = offset_reserved_flags & 1  # No need to shift here as this is the least significant bit
		data = raw_data[offset:]
		return src_port, dest_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data


	# parse raw udp packet
	def udp(self, raw_data):
		src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
		data = raw_data[8:]
		return src_port, dest_port, size, data

 
	# parse raw Ethernet frame
	def ethernet(self, raw_data):
		dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
		dest_mac = self.get_mac_addr(dest)
		src_mac = self.get_mac_addr(src)
		proto = socket.htons(prototype)
		data = raw_data[14:]
		return dest_mac, src_mac, proto, data


	# decode and retrun http packet
	def http(self, raw_data):
		try:
			return raw_data.decode('utf-8')
		except:
			return raw_data


	# parse raw icmp packet
	def icmp(self, raw_data):
		packet_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
		data = raw_data[4:]
		return packet_type, code, checksum, data


