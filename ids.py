import customtkinter as ctk
from scapy.all import sniff, IP, conf
from collections import defaultdict
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

# Configure scapy to use L3 sockets
conf.L3socket=conf.L3socket

class IDSApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window setup
        self.title("Network Intrusion Detection System")
        self.geometry("1000x600")

        # Packet monitoring variables
        self.packet_counts = defaultdict(int)
        self.last_reset = time.time()
        self.threshold = 100  # Packets per second threshold
        self.monitoring = False
        self.packets = []
        self.blocked_ips = set()

        # Create GUI elements
        self.create_gui()

        # Start packet monitoring
        self.start_monitoring()

    def create_gui(self):
        # Create main frame
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)

        # Control panel
        control_frame = ctk.CTkFrame(main_frame)
        control_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.monitor_button = ctk.CTkButton(
            control_frame, 
            text="Start Monitoring", 
            command=self.toggle_monitoring
        )
        self.monitor_button.pack(side="left", padx=5)

        threshold_label = ctk.CTkLabel(control_frame, text="Threshold (packets/sec):")
        threshold_label.pack(side="left", padx=5)

        self.threshold_entry = ctk.CTkEntry(control_frame)
        self.threshold_entry.insert(0, "100")
        self.threshold_entry.pack(side="left", padx=5)

        ip_filter_label = ctk.CTkLabel(control_frame, text="Filter IPs (comma-separated):")
        ip_filter_label.pack(side="left", padx=5)

        self.ip_filter_entry = ctk.CTkEntry(control_frame)
        self.ip_filter_entry.pack(side="left", padx=5)

        # Status label
        self.status_label = ctk.CTkLabel(control_frame, text="Status: Ready")
        self.status_label.pack(side="left", padx=20)

        # Show blocked IPs button
        show_blocked_button = ctk.CTkButton(
            control_frame, 
            text="Show Blocked IPs", 
            command=self.show_blocked_ips
        )
        show_blocked_button.pack(side="left", padx=5)

        # Packet display
        self.packet_tree = ctk.CTkTextbox(main_frame)
        self.packet_tree.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.packet_tree.bind('<Double-Button-1>', self.show_packet_details)

    def toggle_monitoring(self):
        if not self.monitoring:
            try:
                self.monitoring = True
                self.monitor_button.configure(text="Stop Monitoring")
                self.threshold = int(self.threshold_entry.get())
                self.status_label.configure(text="Status: Monitoring")
                self.packet_tree.insert("end", "Started monitoring...\n")
            except Exception as e:
                self.status_label.configure(text=f"Status: Error - {str(e)}")
                self.monitoring = False
                self.monitor_button.configure(text="Start Monitoring")
        else:
            self.monitoring = False
            self.monitor_button.configure(text="Start Monitoring")
            self.status_label.configure(text="Status: Stopped")
            self.packet_tree.insert("end", "Stopped monitoring...\n")

    def start_monitoring(self):
        def packet_callback(packet):
            if not self.monitoring:
                return

            if IP in packet:
                src_ip = packet[IP].src
                self.packet_counts[src_ip] += 1
                
                # Store packet for detailed view
                self.packets.append(packet)
                
                # Update display
                current_time = datetime.now().strftime("%H:%M:%S")
                packet_info = f"[{current_time}] Source IP: {src_ip}, Dest IP: {packet[IP].dst}\n"
                self.packet_tree.insert("end", packet_info)
                self.packet_tree.see("end")

                # Check for flooding
                if self.packet_counts[src_ip] > self.threshold:
                    self.alert_flood(src_ip)

        # Get the IP filter from the entry
        ip_filter = self.ip_filter_entry.get()
        filter_str = "ip"
        if ip_filter:
            ip_list = ip_filter.split(',')
            filter_str = " or ".join([f"host {ip.strip()}" for ip in ip_list])

        # Start packet capture in a separate thread
        try:
            capture_thread = threading.Thread(
                target=lambda: sniff(prn=packet_callback, store=0, filter=filter_str),
                daemon=True
            )
            capture_thread.start()
            
            # Reset counter periodically
            self.reset_counter()
        except Exception as e:
            self.status_label.configure(text=f"Status: Error - {str(e)}")
            messagebox.showerror("Error", f"Failed to start packet capture: {str(e)}")

    def reset_counter(self):
        if self.monitoring:
            elapsed = time.time() - self.last_reset
            if elapsed >= 1:  # Reset every second
                self.packet_counts.clear()
                self.last_reset = time.time()
        self.after(1000, self.reset_counter)

    def alert_flood(self, ip):
        response = messagebox.askyesno(
            "Potential Flood Detected",
            f"High traffic detected from {ip}!\nWould you like to block this IP?"
        )
        if response:
            self.blocked_ips.add(ip)
            messagebox.showinfo("Action Taken", f"IP {ip} has been blocked")

    def show_blocked_ips(self):
        blocked_ips_window = ctk.CTkToplevel(self)
        blocked_ips_window.title("Blocked IP Addresses")
        blocked_ips_window.geometry("400x300")

        blocked_ips_frame = ctk.CTkFrame(blocked_ips_window)
        blocked_ips_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.blocked_ip_vars = {}
        for ip in self.blocked_ips:
            var = tk.BooleanVar()
            chk = ctk.CTkCheckBox(blocked_ips_frame, text=ip, variable=var)
            chk.pack(anchor="w")
            self.blocked_ip_vars[ip] = var

        unblock_button = ctk.CTkButton(
            blocked_ips_window, 
            text="Unblock Selected IPs", 
            command=self.unblock_selected_ips
        )
        unblock_button.pack(pady=10)

    def unblock_selected_ips(self):
        for ip, var in self.blocked_ip_vars.items():
            if var.get():
                self.blocked_ips.remove(ip)
        messagebox.showinfo("Action Taken", "Selected IPs have been unblocked")
        self.show_blocked_ips()

    def show_packet_details(self, event):
        try:
            index = self.packet_tree.index("@%s,%s" % (event.x, event.y))
            line = int(float(index))
            if line < len(self.packets):
                packet = self.packets[line]
                src_ip = packet[IP].src
                details_window = ctk.CTkToplevel(self)
                details_window.title("Packet Details")
                details_window.geometry("600x400")
                
                details_text = ctk.CTkTextbox(details_window)
                details_text.pack(fill="both", expand=True, padx=10, pady=10)
                
                # Format and display packet details
                details = str(packet.show(dump=True))
                details_text.insert("1.0", details)
                details_text.configure(state="disabled")

                block_button = ctk.CTkButton(
                    details_window, 
                    text=f"Block IP {src_ip}", 
                    command=lambda: self.block_ip(src_ip)
                )
                block_button.pack(pady=10)
        except Exception as e:
            messagebox.showerror("Error", f"Could not display packet details: {str(e)}")

    def block_ip(self, ip):
        self.blocked_ips.add(ip)
        messagebox.showinfo("Action Taken", f"IP {ip} has been blocked")

if __name__ == "__main__":
    app = IDSApp()
    app.mainloop()