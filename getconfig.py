import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import threading
import socket
import time
import re
import os

class NetworkConfigApp(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)
        
        # Create a tabview for different network tools
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Create tabs for different functions
        self.tabview.add("IP Config")
        self.tabview.add("ARP Table")
        self.tabview.add("NetCat")
        
        # Setup each tab
        self.setup_ipconfig_tab()
        self.setup_arp_tab()
        self.setup_netcat_tab()
        
    def setup_ipconfig_tab(self):
        tab = self.tabview.tab("IP Config")
        
        # Add control frame
        control_frame = ctk.CTkFrame(tab)
        control_frame.pack(padx=10, pady=5, fill="x")
        
        # Add buttons
        refresh_btn = ctk.CTkButton(control_frame, text="Refresh", command=self.get_ipconfig)
        refresh_btn.pack(side="left", padx=5, pady=5)
        
        # Add dropdown for interface selection
        ctk.CTkLabel(control_frame, text="Interface:").pack(side="left", padx=5, pady=5)
        self.interface_var = ctk.StringVar(value="All")
        self.interfaces = ["All"]
        self.interface_dropdown = ctk.CTkOptionMenu(
            control_frame, 
            values=self.interfaces,
            variable=self.interface_var,
            command=self.get_ipconfig
        )
        self.interface_dropdown.pack(side="left", padx=5, pady=5)
        
        # Add output text area
        self.ipconfig_output = ctk.CTkTextbox(tab, wrap="none", height=400)
        self.ipconfig_output.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Initial load of interfaces and ipconfig data
        self.load_interfaces()
        self.get_ipconfig()
        
    def setup_arp_tab(self):
        tab = self.tabview.tab("ARP Table")
        
        # Add control frame
        control_frame = ctk.CTkFrame(tab)
        control_frame.pack(padx=10, pady=5, fill="x")
        
        # Add buttons
        refresh_btn = ctk.CTkButton(control_frame, text="Refresh", command=self.get_arp_table)
        refresh_btn.pack(side="left", padx=5, pady=5)
        
        clear_btn = ctk.CTkButton(control_frame, text="Clear ARP Cache", command=self.clear_arp_cache)
        clear_btn.pack(side="left", padx=5, pady=5)
        
        # Add output text area
        self.arp_output = ctk.CTkTextbox(tab, wrap="none", height=400)
        self.arp_output.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Initial load of arp table
        self.get_arp_table()
        
    def setup_netcat_tab(self):
        tab = self.tabview.tab("NetCat")
        
        # Add connection settings frame
        settings_frame = ctk.CTkFrame(tab)
        settings_frame.pack(padx=10, pady=10, fill="x")
        
        # Host input
        ctk.CTkLabel(settings_frame, text="Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.host_entry = ctk.CTkEntry(settings_frame, width=200)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Port input
        ctk.CTkLabel(settings_frame, text="Port:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.port_entry = ctk.CTkEntry(settings_frame, width=200)
        self.port_entry.insert(0, "80")
        self.port_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Connection type
        ctk.CTkLabel(settings_frame, text="Mode:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.mode_var = ctk.StringVar(value="Client")
        self.mode_dropdown = ctk.CTkOptionMenu(
            settings_frame,
            values=["Client", "Server"],
            variable=self.mode_var,
            command=self.update_netcat_ui
        )
        self.mode_dropdown.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        # Connect/Disconnect button
        self.connect_btn = ctk.CTkButton(settings_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=3, column=0, columnspan=2, padx=5, pady=10)
        
        # Status label
        self.status_label = ctk.CTkLabel(settings_frame, text="Status: Disconnected", text_color="gray")
        self.status_label.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
        
        # Message input area (for client mode)
        self.input_frame = ctk.CTkFrame(tab)
        self.input_frame.pack(padx=10, pady=5, fill="x")
        
        ctk.CTkLabel(self.input_frame, text="Message:").pack(side="left", padx=5, pady=5)
        self.message_entry = ctk.CTkEntry(self.input_frame, width=300)
        self.message_entry.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        
        self.send_btn = ctk.CTkButton(self.input_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side="left", padx=5, pady=5)
        
        # Output area
        output_frame = ctk.CTkFrame(tab)
        output_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        ctk.CTkLabel(output_frame, text="Communication Log:").pack(anchor="w", padx=5, pady=2)
        self.netcat_output = ctk.CTkTextbox(output_frame, wrap="word", height=300)
        self.netcat_output.pack(padx=5, pady=5, fill="both", expand=True)
        
        # Connection variables
        self.connected = False
        self.socket = None
        self.server_socket = None
        self.client_socket = None
        
        # Update UI based on initial mode
        self.update_netcat_ui(self.mode_var.get())
        
    def load_interfaces(self):
        """Load network interfaces for the dropdown"""
        try:
            # Use ipconfig to get interface names
            result = subprocess.run(
                ["ipconfig"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            # Simple parsing to extract interface names from ipconfig output
            interfaces = ["All"]
            for line in result.stdout.split('\n'):
                if re.match(r'^\w', line) and ':' in line:
                    interface = line.split(':')[0].strip()
                    interfaces.append(interface)
            
            # Update dropdown
            self.interfaces = interfaces
            self.interface_dropdown.configure(values=interfaces)
            self.interface_var.set("All")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get network interfaces: {str(e)}")
    
    def get_ipconfig(self, *args):
        """Get and display ipconfig information"""
        try:
            selected_interface = self.interface_var.get()
            
            # Run ipconfig command
            if selected_interface == "All":
                cmd = ["ipconfig", "/all"]
            else:
                # Filter output for specific interface
                cmd = ["ipconfig", "/all"]
                
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = result.stdout
            
            # If a specific interface is selected, filter the output
            if selected_interface != "All":
                filtered_output = ""
                capture = False
                for line in output.split('\n'):
                    if re.match(r'^\w', line) and ':' in line:
                        if selected_interface in line:
                            capture = True
                        else:
                            capture = False
                    
                    if capture:
                        filtered_output += line + '\n'
                
                output = filtered_output if filtered_output else "Interface not found."
            
            # Display in the text box
            self.ipconfig_output.configure(state="normal")
            self.ipconfig_output.delete("1.0", "end")
            self.ipconfig_output.insert("1.0", output)
            self.ipconfig_output.configure(state="disabled")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get ipconfig information: {str(e)}")
    
    def get_arp_table(self):
        """Get and display ARP table"""
        try:
            # Run arp command
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=True)
            output = result.stdout
            
            # Display in the text box
            self.arp_output.configure(state="normal")
            self.arp_output.delete("1.0", "end")
            self.arp_output.insert("1.0", output)
            self.arp_output.configure(state="disabled")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get ARP table: {str(e)}")
    
    def clear_arp_cache(self):
        """Clear the ARP cache (requires admin privileges)"""
        try:
            # Prompt for confirmation
            response = messagebox.askyesno(
                "Confirm", 
                "Clearing the ARP cache requires administrator privileges.\n\nDo you want to continue?"
            )
            
            if response:
                if os.name == 'nt':  # Windows
                    # Using netsh to clear ARP cache
                    result = subprocess.run(
                        ["netsh", "interface", "ip", "delete", "arpcache"], 
                        capture_output=True, 
                        text=True, 
                        check=True
                    )
                else:  # Linux/Unix
                    result = subprocess.run(
                        ["ip", "neigh", "flush", "all"], 
                        capture_output=True, 
                        text=True, 
                        check=True
                    )
                
                messagebox.showinfo("Success", "ARP cache cleared successfully.")
                # Refresh the ARP table display
                self.get_arp_table()
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear ARP cache: {str(e)}\n\nMake sure you are running as administrator.")
    
    def update_netcat_ui(self, mode):
        """Update UI based on selected mode (client/server)"""
        if mode == "Client":
            self.connect_btn.configure(text="Connect")
            self.input_frame.pack(padx=10, pady=5, fill="x")
        else:  # Server
            self.connect_btn.configure(text="Start Server")
            self.input_frame.pack_forget()  # Hide input in server mode
    
    def toggle_connection(self):
        """Toggle connection state (connect/disconnect or start/stop server)"""
        if not self.connected:
            # Start connection
            if self.mode_var.get() == "Client":
                self.start_client()
            else:
                self.start_server()
        else:
            # Stop connection
            self.stop_connection()
    
    def start_client(self):
        """Start netcat client connection"""
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            
            # Update UI
            self.connected = True
            self.connect_btn.configure(text="Disconnect")
            self.status_label.configure(text=f"Status: Connected to {host}:{port}", text_color="green")
            
            # Start receive thread
            threading.Thread(target=self.receive_data, daemon=True).start()
            
            # Log connection
            self.log_message(f"Connected to {host}:{port}")
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
    
    def start_server(self):
        """Start netcat server"""
        try:
            host = self.host_entry.get() or "0.0.0.0"
            port = int(self.port_entry.get())
            
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(1)
            
            # Update UI
            self.connected = True
            self.connect_btn.configure(text="Stop Server")
            self.status_label.configure(text=f"Status: Listening on {host}:{port}", text_color="blue")
            
            # Log
            self.log_message(f"Server started on {host}:{port}")
            
            # Start accept thread
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Server Error", f"Failed to start server: {str(e)}")
    
    def accept_connections(self):
        """Accept incoming connections (server mode)"""
        try:
            while self.connected:
                try:
                    self.log_message("Waiting for connections...")
                    client_socket, addr = self.server_socket.accept()
                    self.client_socket = client_socket
                    
                    self.log_message(f"Client connected: {addr[0]}:{addr[1]}")
                    
                    # Start receive thread for this client
                    threading.Thread(target=self.receive_client_data, args=(client_socket, addr), daemon=True).start()
                except:
                    # If the server socket is closed, break the loop
                    if not self.connected:
                        break
                    time.sleep(0.1)
                    
        except Exception as e:
            if self.connected:  # Only show error if still supposed to be running
                self.log_message(f"Error accepting connections: {str(e)}")
    
    def receive_client_data(self, client_socket, addr):
        """Receive data from a connected client"""
        try:
            while self.connected:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                message = data.decode('utf-8', errors='replace')
                self.log_message(f"Received from {addr[0]}:{addr[1]}: {message}")
                
            client_socket.close()
            self.log_message(f"Client disconnected: {addr[0]}:{addr[1]}")
            
        except Exception as e:
            if self.connected:  # Only show error if still supposed to be running
                self.log_message(f"Error receiving from client: {str(e)}")
    
    def receive_data(self):
        """Receive data (client mode)"""
        try:
            while self.connected:
                data = self.socket.recv(1024)
                if not data:
                    break
                
                message = data.decode('utf-8', errors='replace')
                self.log_message(f"Received: {message}")
                
            if self.connected:  # If we're still supposed to be connected, this means the server closed
                self.log_message("Server closed the connection.")
                self.stop_connection()
                
        except Exception as e:
            if self.connected:  # Only show error if still supposed to be running
                self.log_message(f"Error receiving data: {str(e)}")
                self.stop_connection()
    
    def send_message(self):
        """Send a message (client mode)"""
        if not self.connected:
            messagebox.showwarning("Not Connected", "Please connect first before sending messages.")
            return
            
        try:
            message = self.message_entry.get()
            if message:
                if self.mode_var.get() == "Client":
                    self.socket.sendall(message.encode('utf-8'))
                else:
                    if self.client_socket:
                        self.client_socket.sendall(message.encode('utf-8'))
                    else:
                        self.log_message("No client connected. Cannot send message.")
                        return
                
                self.log_message(f"Sent: {message}")
                self.message_entry.delete(0, "end")  # Clear input field
                
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {str(e)}")
            self.stop_connection()
    
    def stop_connection(self):
        """Stop current connection (client or server)"""
        self.connected = False
        
        try:
            # Close client socket
            if self.socket:
                self.socket.close()
                self.socket = None
            
            # Close server socket
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            
            # Close connected client socket (server mode)
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            
            # Update UI
            mode = self.mode_var.get()
            if mode == "Client":
                self.connect_btn.configure(text="Connect")
            else:
                self.connect_btn.configure(text="Start Server")
            
            self.status_label.configure(text="Status: Disconnected", text_color="gray")
            self.log_message("Disconnected.")
            
        except Exception as e:
            self.log_message(f"Error disconnecting: {str(e)}")
    
    def log_message(self, message):
        """Log a message to the output textbox"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.netcat_output.configure(state="normal")
        self.netcat_output.insert("end", log_entry)
        self.netcat_output.see("end")  # Scroll to bottom
        self.netcat_output.configure(state="disabled")


# Standalone test
if __name__ == "__main__":
    app = ctk.CTk()
    app.title("Network Configuration Tools")
    app.geometry("800x600")
    NetworkConfigApp(app)
    app.mainloop()