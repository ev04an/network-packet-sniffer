import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP

# GUI Setup
root = tk.Tk()
root.title("Network Packet Sniffer")
root.geometry("600x400")

# Textbox to display packets
text_area = tk.Text(root, height=20, width=70)
text_area.pack()

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

        packet_info = f"{ip_src} → {ip_dst} | Protocol: {protocol_name} | Port: {port}\n"
        text_area.insert(tk.END, packet_info)

# Start sniffing
def start_sniffing():
    text_area.insert(tk.END, "Starting packet sniffing...\n")
    sniff(prn=process_packet, store=False)

# Start Button
start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack()

# Run the GUI
root.mainloop()
