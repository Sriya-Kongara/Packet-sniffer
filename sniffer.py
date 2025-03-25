import scapy.all as scapy
import argparse

# Set up command-line argument parsing
parser = argparse.ArgumentParser(description="Network Packet Analyzer")
parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff (e.g., eth0, wlan0)")
args = parser.parse_args()

# Create a dictionary to store packet statistics
packet_stats = {}

# Dictionary to map port numbers to protocol names
port_to_protocol = {
    80: "HTTP",
    443: "HTTPS",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    53: "DNS",
    21: "FTP",
    22: "SSH",
    23: "Telnet"
}

def get_protocol_name(packet):
    """Return the protocol name based on the port numbers or protocol field."""
    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
        sport = packet.sport
        dport = packet.dport
        if sport in port_to_protocol:
            return port_to_protocol[sport]
        elif dport in port_to_protocol:
            return port_to_protocol[dport]
    if packet.haslayer(scapy.IP):
        proto = packet[scapy.IP].proto
        if proto == 6:
            return "TCP"
        elif proto == 17:
            return "UDP"
        elif proto == 1:
            return "ICMP"
    return "Other"

def analyze_packet(packet):
    try:
        # Get the protocol name
        protocol = get_protocol_name(packet)
        
        # Get the source and destination IP addresses
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        # Get the source and destination port numbers (if applicable)
        src_port = packet.sport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else None
        dst_port = packet.dport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else None

        # Update the packet statistics
        if protocol not in packet_stats:
            packet_stats[protocol] = {"count": 1, "src_ips": {src_ip: 1}, "dst_ips": {dst_ip: 1}}
        else:
            packet_stats[protocol]["count"] += 1
            packet_stats[protocol]["src_ips"][src_ip] = packet_stats[protocol]["src_ips"].get(src_ip, 0) + 1
            packet_stats[protocol]["dst_ips"][dst_ip] = packet_stats[protocol]["dst_ips"].get(dst_ip, 0) + 1

        # Print the packet details
        print(f"Protocol: {protocol}, Src IP: {src_ip}, Dst IP: {dst_ip}, Src Port: {src_port}, Dst Port: {dst_port}")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    print(f"Starting packet sniffing on interface {args.interface}. Press Ctrl+C to stop.")
    try:
        scapy.sniff(iface=args.interface, prn=analyze_packet)
    except Exception as e:
        print(f"An error occurred during packet sniffing: {e}")
    finally:
        # Print the packet statistics
        print("\nPacket Statistics:")
        for protocol, stats in packet_stats.items():
            print(f"Protocol: {protocol}, Count: {stats['count']}, Src IPs: {stats['src_ips']}, Dst IPs: {stats['dst_ips']}")

if __name__ == "__main__":
    main()