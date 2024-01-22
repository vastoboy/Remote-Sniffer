import socket
import struct


class Protocols:
	# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
	def get_mac_addr(self, mac_raw):
	    byte_str = map('{:02x}'.format, mac_raw)
	    mac_addr = ':'.join(byte_str).upper()
	    return mac_addr


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



	def tcp(self, raw_data):
		(src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
		offset = (offset_reserved_flags >> 12) * 4
		flag_urg = (offset_reserved_flags & 32) >> 5
		flag_ack = (offset_reserved_flags & 16) >> 4
		flag_psh = (offset_reserved_flags & 8) >> 3
		flag_rst = (offset_reserved_flags & 4) >> 2
		flag_syn = (offset_reserved_flags & 2) >> 1
		flag_fin = offset_reserved_flags & 1
		data = raw_data[offset:]
		return src_port, dest_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data


	def udp(self, raw_data):
		src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
		data = raw_data[8:]
		return src_port, dest_port, size, data

 

	def ethernet(self, raw_data):
		dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
		dest_mac = self.get_mac_addr(dest)
		src_mac = self.get_mac_addr(src)
		proto = socket.htons(prototype)
		data = raw_data[14:]
		return dest_mac, src_mac, proto, data



	def http(self, raw_data):
		try:
			data = raw_data.decode('utf-8')
			return data
		except:
			data = raw_data
			return data



	def icmp(self, raw_data):
		packet_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
		data = raw_data[4:]
		return packet_type, code, checksum, data




