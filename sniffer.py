import csv
from scapy.all import sniff, IP, TCP, UDP

# Create or open a CSV file
csv_filename = "captured_packets.csv"

# Write CSV Header
with open(csv_filename, mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Source IP", "Destination IP", "Protocol", "Port"])

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol_name = "Other"
        port = "N/A"
        
        if TCP in packet:
            protocol_name = "TCP"
            port = packet[TCP].dport
        elif UDP in packet:
            protocol_name = "UDP"
            port = packet[UDP].dport
        
        print(f"Packet: {ip_src} → {ip_dst} | Protocol: {protocol_name} | Port: {port}")

        # Write packet data to CSV
        with open(csv_filename, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([ip_src, ip_dst, protocol_name, port])

# Start sniffing
print("Sniffing packets... Packets will be saved in captured_packets.csv")
sniff(prn=process_packet, store=False)
