from scapy.all import *

def packet_sniffer(packet):
    if IP in packet:
        # Extract IP layer information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Print basic information
        print(f"IP Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

        # Check if TCP or UDP layer present
        if TCP in packet:
            # Extract TCP layer information
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = packet[TCP].payload

            # Print TCP information
            print(f"TCP Port: {src_port} -> {dst_port} | Payload: {payload}")

        elif UDP in packet:
            # Extract UDP layer information
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = packet[UDP].payload

            # Print UDP information
            print(f"UDP Port: {src_port} -> {dst_port} | Payload: {payload}")

# Start sniffing packets
print("Starting packet sniffer...")
sniff(prn=packet_sniffer, store=0)
