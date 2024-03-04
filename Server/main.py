#Created by Vasto Boy

#Disclaimer: This packet sniffer should only be used in the lawful, remote administration of authorized systems. Accessing a computer network without authorization or permission is illegal.

import os
import re
import json
import time
import socket
import struct
import textwrap
import threading
from datetime import datetime
from esHandler import EsHandler
from getmac import get_mac_address as gma



class SimpleSnifferServer:

        def __init__(self, host, port, index_name, es_url):
            self.host = host
            self.port = port
            self.sock = None
            self.eshandler = EsHandler(index_name, es_url)



        #create socket and listen for client connections
        def create_socket(self):
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.bind((self.host, self.port))
                self.sock.listen(5) #listen for connection
                print(f"Listening on {self.port}!!!")
            except socket.error as err:
                print("[-]Error unable to create socket!!!" + str(err))



        #handles incoming connection
        def handle_client(self):
            while True:
                try:
                    conn, addr = self.sock.accept()
                    conn.setblocking(True)
                    client_data = conn.recv(1024).decode() #recieve response from client
                    ip = re.findall("'(.*?)'", str(addr)) #format IP from addr
                    ip = {"ip": "".join(ip)}

                    client_data = json.loads(client_data)
                    client_data_dict = ip.copy() #prepend ip to the start of the dictionary
                    client_data_dict.update(client_data)
                    self.eshandler.store_client_information(client_data_dict)

                    if conn:
                        self.receive_captures(conn)
                        break
                except KeyboardInterrupt:
                    break



        def change_text_color(self, text):
            RESET = "\033[0m"
            BOLD = "\033[1m"
            COLOR = "\u001b[36m" 
            return f"{BOLD}{COLOR}{text}{RESET}"



         #shell interface
        def shell_interface(self):
                while True:
                    print(self.change_text_color("Sniffer: "), end="")
                    cmd = input()
                    cmd = cmd.rstrip()

                    if cmd == '':
                        pass

                    elif cmd.strip() == 'clients':
                        self.eshandler.retrieve_client_information()

                    elif 'delete all' in cmd:
                        self.eshandler.delete_all_docs()


                    elif 'delete' in cmd:
                        client_id = cmd[7:]
                        self.eshandler.delete_document(client_id)


                   

        def receive_captures(self, conn):
            while True:
                try:
                    # Receive captures from client machine
                    capture_bytes = self.recvall(conn)
                    if capture_bytes:
                        captures_json = capture_bytes.decode()
                        captures = json.loads(captures_json, parse_int=str)
                        for capture in captures:
                            # Loop through all keys in capture
                            for key in list(capture.keys()):
                                if key.endswith("Data") and capture[key]:
                                    # Decode hex data
                                    hex_data = capture[key]
                                    decoded_data = bytes.fromhex(hex_data).decode('utf-8', errors='ignore')  # errors='ignore' to avoid decoding issues
                                    capture[key] = decoded_data

                            print(capture)
                            print("\n")
                            self.eshandler.index_capture(capture)
                    else:
                        #print("No data received from client")
                        continue
                except Exception as e:
                    print(f"Error occurred while receiving captures: {e}")
                    continue
                    



        def recvall(self, conn, buffer_size=8192):
            data = bytearray()
            while True:
                data_chunk = conn.recv(buffer_size)
                data += data_chunk
                if len(data_chunk) < buffer_size:
                    # Either 0 or end of data
                    break
            return data



        def handle_packets(self, conn):
            while True:
                packet_capture = self.recv_msg(conn)
                print(f"Capture: {packet_capture}")



        def start(self):
            self.create_socket()
            self.handle_client()





art = """
███████╗██╗███╗   ███╗██████╗ ██╗     ███████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔════╝██║████╗ ████║██╔══██╗██║     ██╔════╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██║██╔████╔██║██████╔╝██║     █████╗      ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝      ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║██║ ╚═╝ ██║██║     ███████╗███████╗    ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
""" 

print(art)




sniffer = SimpleSnifferServer("192.168.1.182", 5001, "packet-sniffer", "http://localhost:9200")

# Create two threads for the functions
thread1 = threading.Thread(target=sniffer.start)
thread1.start()

thread2 = threading.Thread(target=sniffer.shell_interface)
thread2.start() # Start the threads

