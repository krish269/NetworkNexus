# packet_sniffer.py
from scapy.all import sniff, IP, TCP, UDP, Ether, DNS
import threading


class PacketSniffer:
    def __init__(self):
        self.running = False
        self.packets = []

    def start_sniffing(self):
        """Start the packet sniffing in a separate thread."""
        self.running = True
        threading.Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):
        """Stop the packet sniffing."""
        self.running = False

    def sniff_packets(self):
        """Capture packets and append them to the list."""
        sniff(prn=self.process_packet, store=0)

    def process_packet(self, packet):
        """Process captured packets and store them."""
        if not self.running:
            return

        self.packets.append(packet)

    def get_packets(self):
        """Return captured packets."""
        return self.packets

    def filter_packets(self, protocol=None, ip=None):
        """Filter captured packets based on protocol or IP address."""
        filtered_packets = []
        for packet in self.packets:
            if protocol and packet.haslayer(protocol):
                filtered_packets.append(packet)
            elif ip and (packet[IP].src == ip or packet[IP].dst == ip):
                filtered_packets.append(packet)
        return filtered_packets

    def get_statistics(self):
        """Generate statistics from captured packets."""
        stats = {
            'total_packets': len(self.packets),
            'tcp_packets': len(self.filter_packets(TCP)),
            'udp_packets': len(self.filter_packets(UDP)),
            'ip_packets': len(self.filter_packets(IP)),
            'http_packets': self.count_http_packets(),
            'dns_packets': len(self.filter_packets(DNS))
        }
        return stats

    def count_http_packets(self):
        """Count packets that contain HTTP data."""
        http_count = 0
        for packet in self.packets:
            if packet.haslayer(TCP):
                # Check if TCP payload contains 'HTTP' method keywords
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    if b'GET ' in bytes(packet[TCP].payload) or b'POST ' in bytes(packet[TCP].payload):
                        http_count += 1
        return http_count

    def inspect_packet(self, packet):
        """Get a detailed string representation of a packet."""
        return packet.show(dump=True)  # Returns detailed packet info as string
