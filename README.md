# Packet-sniffer                  
**NETWORK PACKET SNIFFER**                            


**ABSTRACT:**                                    
The network packet sniffer is designed to capture and analyze real-time network traffic on a specified interface. This project provides deep visibility into network activity by categorizing packets based on protocols (http, https, tcp, udp, etc.) And extracting essential information such as source and destination ip addresses and port numbers. Utilizing python's scapy library for efficient packet inspection and the npcap library for low-level packet capture on windows, this tool facilitates real-time traffic monitoring and network diagnostics. Our project applications include: 
Network security analysis: monitors traffic for anomalous patterns, and vulnerabilities. 
Troubleshooting: identifying and resolving network issues to ensure optimal performance. 
Traffic monitoring: understanding communication patterns and usage trends. This project is valuable for it professionals, security analysts, and network researchers aiming to enhance security and optimize network performance.

**INTRODUCTION:**                           
A packet sniffer, also known as a network analyzer or protocol analyzer, is a tool used to capture and examine the data packets transmitted over a network. 
Packet sniffers work by intercepting these packets as they travel across the network, decoding the data, and providing a detailed view of network traffic
While packet sniffers are essential for diagnosing network problems and enhancing security, they must be used responsibly. Unauthorized packet sniffing can lead to privacy breaches and legal consequences, as it can expose sensitive data being transferred over the network.

**METHODOLOGY:**                                              
1. Network interface selection: our work is initialized by selecting a network interface for packet capture. The user specifies the interface (e.G., Eth0 for ethernet, wlan0 for wi-fi) to monitor, allowing targeted network analysis.
Eg: python file_name.Py -i <interface>


2. Packet capture and protocol identification: using the scapy library, packets are captured in real-time. Each packet is examined to determine its protocol type based on port numbers or IP protocol fields. A dictionary maps specific ports to common protocols (e.G., HTTP, HTTPS, UDP, TCP, DNS) to facilitate this classification.


3. Packet analysis : for each captured packet, the script extracts essential details such as the protocol, source IP, destination IP, source port, and destination port. 

4. Data logging and summary statistics: the packet sniffer maintains a summary of the captured data, including packet counts by protocol and the frequency of source and destination ips. This summary is printed to the console upon completion, providing an overview of network activity during the sniffing session.


5. Error handling: robust error handling ensures that unexpected packet structures do not interrupt the packet capture process. By checking for the presence of necessary packet layers, the tool gracefully handles various packet formats and network anomalies.

**RESULTS:**                                               
The output of the packet sniffer shows network traffic captured on the `wi-fi` interface. It logs communication between various devices using DNS and HTTPS protocols. For DNS traffic, the sniffer captures 4 packets exchanged between two local devices, `192.168.27.249` and `192.168.27.155`, with each device sending and receiving two packets. The captured HTTPS traffic involves communication between the local device `192.168.27.249` and an external server at `20.42.73.28`, with a total of 4 packets exchanged, where the local device initiates most of the communication. The packet statistics summary provides a count of packets for each protocol and lists the source and destination ips involved, offering insights into the types of communication and the devices interacting on the network.

**CONCLUSION:**                                             
In conclusion, packet sniffing is an essential technique for monitoring and analysing network traffic, providing valuable insights into network performance, security, and troubleshooting. Throughout this project, we have explored how packet sniffers capture and decode data packets, allowing us to observe network behaviour in real-time.

