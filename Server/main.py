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


                    elif 'delete' in cmd:
                        client_id = cmd[7:]
                        self.eshandler.delete_document(client_id)




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



sniffer = SimpleSnifferServer("192.168.1.182", 5005, "packet-sniffer", "http://localhost:9200")

# Create two threads for the functions
thread1 = threading.Thread(target=sniffer.start)
thread2 = threading.Thread(target=sniffer.shell_interface)

# Start the threads
thread1.start()
thread2.start()




