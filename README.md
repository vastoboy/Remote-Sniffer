# Packet-Sniffer
Remote Sniffer is a simple Python-based tool designed to remotely capture and analyze network packets. It allows users to monitor network traffic in real-time, capturing packets sent and received over a network interface.


  ## Internet Header Format

```

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

## Setup Elasticsearch
* Before using Packet-Sniffer, ensure that you have Elasticsearch installed and configured. Elasticsearch is used for storing and indexing captured packet data. Follow these steps to set up Elasticsearch:

* Install Elasticsearch: Download and install Elasticsearch from the official Elasticsearch website.

* Start Elasticsearch: Start the Elasticsearch service using the appropriate method for your operating system. Refer to the Elasticsearch documentation for detailed instructions on how to start the service.

* Configure Elasticsearch: Optionally, configure Elasticsearch settings such as cluster name, node settings, network host, etc., as per your requirements. Refer to the Elasticsearch documentation for guidance on configuration options.

* Verify Elasticsearch Setup: Confirm that Elasticsearch is running and accessible by visiting http://localhost:9200 in your web browser. You should see a JSON response indicating the Elasticsearch cluster status.

* Create Elasticsearch Index: Create an index in Elasticsearch to store the captured packet data. You can use the Elasticsearch API or tools like Kibana to create the index with the desired settings and mappings.

* Once Elasticsearch is set up and configured, you can start using Packet-Sniffer to capture and analyze network packets, with the captured data being stored in Elasticsearch for further analysis and visualization.


## Features

* Remote Packet Capture: Capture network packets remotely.
* Server-Client Architecture: Consists of a server program for capturing packets and a client program for sending the captured packets back to the server.
* Elasticsearch Integration: Save captured packets in an Elasticsearch index for storage and analysis.
* Reverse Shell: Includes a reverse shell feature for starting or stopping the packet sniffer remotely.


## Installation
Remote Sniffer requires Python 3 and certain dependencies. Use pip to install the required packages:

`pip install -r requirements.txt`



## Usage 
```

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

```



## Disclaimer

This code is intended for educational and informational purposes only. Use it responsibly and ensure compliance with applicable laws and regulations. Respect the privacy and security of others.  
The author of this code assume no liability and is not responsible for misuses or damages caused by any code contained in this repository in any event that, accidentally or otherwise, it comes to be utilized by a threat agent or unauthorized entity as a means to compromise the security, privacy, confidentiality, integrity, and/or availability of systems and their associated resources. In this context the term "compromise" is henceforth understood as the leverage of exploitation of known or unknown vulnerabilities present in said systems, including, but not limited to, the implementation of security controls, human- or electronically-enabled.


