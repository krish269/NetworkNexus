import customtkinter as ctk
from portscanner_copy import ping_function, main, portscannez
from chat import PacketAnalyzer
from traceroute import TracerouteVisualizerApp

import arp
from firewall import FirewallApp  
import re
import subprocess
import tkinter as tk
from tkinter import messagebox
import sys
import os
import threading
import time
import psutil
from datetime import datetime
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Add import at the top of the file
from getconfig import NetworkConfigApp

class BandwidthMonitor:
    def __init__(self, parent, notification_callback=None):
        self.parent = parent
        self.notification_callback = notification_callback

        # Store previous measurements
        self.prev_io = None
        self.threshold = 100.0  # Default 100 MB/s
        self.alert_active = False
        self.running = True

        # Store data for graphing
        self.time_data = []
        self.upload_data = []
        self.download_data = []
        self.total_data = []
        self.max_data_points = 60  # 1 minute of data

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.monitor_thread.start()

    def set_threshold(self, threshold):
        """Update the bandwidth threshold"""
        try:
            new_threshold = float(threshold)
            if new_threshold <= 0:
                raise ValueError("Threshold must be positive")
            self.threshold = new_threshold
            # Reset alert status if it was active
            if self.alert_active:
                self.alert_active = False
            return True
        except ValueError:
            return False

    def convert_bytes(self, bytes_amount):
        """Convert bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_amount < 1024.0:
                return f"{bytes_amount:.2f} {unit}/s"
            bytes_amount /= 1024.0
        return f"{bytes_amount:.2f} TB/s"

    def bytes_to_mb(self, bytes_amount):
        """Convert bytes to MB for threshold comparison"""
        return bytes_amount / (1024 * 1024)

    def bytes_to_kb(self, bytes_amount):
        """Convert bytes to KB for graphing"""
        return bytes_amount / 1024

    def monitor_network(self):
        """Main monitoring loop"""
        start_time = time.time()
        while self.running:
            try:
                io = psutil.net_io_counters()

                if self.prev_io is not None:
                    # Calculate speeds
                    upload_bytes = io.bytes_sent - self.prev_io.bytes_sent
                    download_bytes = io.bytes_recv - self.prev_io.bytes_recv
                    
                    # Calculate total
                    total_bytes = upload_bytes + download_bytes
                    total_mb = self.bytes_to_mb(total_bytes)
                    
                    # Update data for graph
                    current_time = time.time() - start_time
                    self.time_data.append(current_time)
                    self.upload_data.append(self.bytes_to_kb(upload_bytes))
                    self.download_data.append(self.bytes_to_kb(download_bytes))
                    self.total_data.append(self.bytes_to_kb(total_bytes))
                    
                    # Limit data points
                    if len(self.time_data) > self.max_data_points:
                        self.time_data.pop(0)
                        self.upload_data.pop(0)
                        self.download_data.pop(0)
                        self.total_data.pop(0)

                    # Check if we're exceeding threshold
                    if total_mb > self.threshold and not self.alert_active:
                        self.alert_active = True
                        if self.notification_callback:
                            message = f"Network flood detected! Traffic: {self.convert_bytes(total_bytes)}"
                            self.notification_callback(message)
                    elif total_mb <= self.threshold and self.alert_active:
                        self.alert_active = False

                self.prev_io = io
            except Exception as e:
                print(f"Error in monitoring: {str(e)}")

            time.sleep(1)

    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)


class BandwidthMonitorUI(ctk.CTkFrame):
    def __init__(self, parent, monitor):
        super().__init__(parent)
        self.monitor = monitor
        self.setup_gui()

    def setup_gui(self):
        # Stats frame for displaying current speeds
        stats_frame = ctk.CTkFrame(self)
        stats_frame.pack(fill="x", padx=10, pady=10)

        # Create speed labels with improved styling
        self.upload_label = ctk.CTkLabel(stats_frame, text="Upload Speed: waiting for data...",
                                      font=("Helvetica", 12))
        self.download_label = ctk.CTkLabel(stats_frame, text="Download Speed: waiting for data...",
                                        font=("Helvetica", 12))
        self.total_label = ctk.CTkLabel(stats_frame, text="Total Speed: waiting for data...",
                                      font=("Helvetica", 12))

        self.upload_label.pack(pady=5, anchor="w")
        self.download_label.pack(pady=5, anchor="w")
        self.total_label.pack(pady=5, anchor="w")

        # Status indicator
        self.status_label = ctk.CTkLabel(stats_frame, text="Status: Normal",
                                      text_color="green", font=("Helvetica", 14, "bold"))
        self.status_label.pack(pady=10)

        # Threshold controls frame
        threshold_frame = ctk.CTkFrame(self)
        threshold_frame.pack(fill="x", padx=10, pady=10)

        # Title for threshold settings
        threshold_title = ctk.CTkLabel(threshold_frame, text="Flood Detection Settings", 
                                     font=("Helvetica", 12, "bold"))
        threshold_title.pack(anchor="w", padx=5, pady=5)

        # Threshold adjustment controls
        controls_frame = ctk.CTkFrame(threshold_frame)
        controls_frame.pack(fill="x", padx=5, pady=5)

        ctk.CTkLabel(controls_frame, text="Threshold (MB/s):",
                   font=("Helvetica", 12)).pack(side="left", padx=5)

        self.threshold_entry = ctk.CTkEntry(controls_frame, width=80)
        self.threshold_entry.insert(0, str(self.monitor.threshold))
        self.threshold_entry.pack(side="left", padx=5)

        update_button = ctk.CTkButton(controls_frame, text="Update",
                                    command=self.update_threshold)
        update_button.pack(side="left", padx=5)
        
        # Add a reset button
        reset_button = ctk.CTkButton(
            controls_frame,
            text="Reset to Default",
            command=lambda: [self.threshold_entry.delete(0, "end"), 
                           self.threshold_entry.insert(0, "100.0"),
                           self.update_threshold()]
        )
        reset_button.pack(side="left", padx=5)
        
        # Current threshold display
        self.threshold_label = ctk.CTkLabel(threshold_frame, 
                                         text=f"Current Threshold: {self.monitor.threshold} MB/s")
        self.threshold_label.pack(anchor="w", padx=5, pady=5)

        # Graph frame
        graph_frame = ctk.CTkFrame(self)
        graph_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create matplotlib figure for network traffic visualization
        self.fig = Figure(figsize=(6, 3), dpi=100)
        self.plot = self.fig.add_subplot(111)
        self.plot.set_title('Network Traffic')
        self.plot.set_xlabel('Time (s)')
        self.plot.set_ylabel('Speed (KB/s)')
        self.plot.grid(True)

        # Create canvas to display the figure
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Start GUI updates
        self.update_gui()

    def update_threshold(self):
        """Update the bandwidth threshold"""
        new_threshold = self.threshold_entry.get()
        if self.monitor.set_threshold(new_threshold):
            self.threshold_label.configure(text=f"Current Threshold: {new_threshold} MB/s")
            messagebox.showinfo("Threshold Updated", f"Bandwidth threshold updated to {new_threshold} MB/s")
            
            # Reset status if it was in alert mode
            if self.monitor.alert_active:
                self.status_label.configure(text="Status: Normal", text_color="green")
        else:
            messagebox.showerror("Invalid Input", "Please enter a positive number for the threshold")

    def update_gui(self):
        """Update GUI with current data"""
        if len(self.monitor.time_data) > 0:
            # Get latest values
            latest_upload = self.monitor.upload_data[-1] * 1024  
            latest_download = self.monitor.download_data[-1] * 1024
            latest_total = self.monitor.total_data[-1] * 1024

            # Update labels
            self.upload_label.configure(text=f"Upload Speed: {self.monitor.convert_bytes(latest_upload)}")
            self.download_label.configure(text=f"Download Speed: {self.monitor.convert_bytes(latest_download)}")
            self.total_label.configure(text=f"Total Speed: {self.monitor.convert_bytes(latest_total)}")

            # Update status indicator
            if self.monitor.alert_active:
                self.status_label.configure(text="Status: TRAFFIC FLOOD DETECTED!", text_color="red")
            else:
                self.status_label.configure(text="Status: Normal", text_color="green")

            try:
                # Clear the plot and add new data
                self.plot.clear()
                self.plot.plot(self.monitor.time_data, self.monitor.upload_data, 'g-', label='Upload')
                # Fix: Use self.monitor.download_data instead of self.download_data
                self.plot.plot(self.monitor.time_data, self.monitor.download_data, 'b-', label='Download')
                # Fix: Use self.monitor.total_data instead of self.total_data
                self.plot.plot(self.monitor.time_data, self.monitor.total_data, 'r-', label='Total')

                # Update plot labels and appearance
                self.plot.set_title('Network Traffic')
                self.plot.set_xlabel('Time (s)')
                self.plot.set_ylabel('Speed (KB/s)')
                self.plot.grid(True)
                self.plot.legend(loc='upper left')

                # Set the y-axis limits with some headroom
                if self.monitor.total_data:
                    max_value = max(max(self.monitor.total_data), 1)  # Avoid divisions by zero
                    self.plot.set_ylim([0, max_value * 1.2])  # 20% headroom

                # Redraw the canvas
                self.canvas.draw()
            except Exception as e:
                print(f"Error updating plot: {str(e)}")

        # Schedule the next update
        self.after(1000, self.update_gui)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Basic UI setup (labels, entries, etc.)
        self.title('Network Nexus Application')
        self.geometry(f'{self.winfo_screenwidth()}x{self.winfo_screenheight()}-10-10')
        self._set_appearance_mode('system')  
        self.state('normal')

        self.grid_rowconfigure(4, weight=1)  
        self.grid_columnconfigure((0, 1), weight=1)
        
        # Initialize bandwidth monitor BEFORE UI creation
        self.bandwidth_monitor = BandwidthMonitor(self, self.show_notification)
        
        # Create all UI elements
        self._create_ui()
        
        # Store references to windows
        self.arp_spoof_window = None
        self.firewall_window = None
        self.network_config_window = None
        
    def _create_ui(self):
        """Create all UI elements"""
        # This method just groups UI creation to keep __init__ cleaner
        ctk.CTkLabel(
            self, text='🌐 Welcome to the Network Nexus 🌐', 
            font=('Arial', 28, 'bold'), 
            fg_color='transparent'
        ).grid(row=0, column=0, columnspan=2, pady=20)

        self._create_label_and_entry('Select Domain/IP Address:', row=1, placeholder='e.g., google.com')

        self.operation = self._create_label_and_option_menu(
            'Select Operation:', 
            ['Ping', 'Port Scan', 'Packet Analysis', 'Trace Route', 
             'ARP Spoof', 'Firewall', 'Bandwidth Monitor', 'Network Config'], 
            row=2, command=self.operation_selected
        )

        self.traceroute_frame = ctk.CTkFrame(self)
        self.traceroute_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        self.traceroute_frame.grid_remove()  

        self.submit_btn = ctk.CTkButton(self, text='Submit', command=self.domain_entry, width=200)
        self.submit_btn.grid(row=3, column=0, columnspan=2, pady=10)

        self.results_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.results_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        self.result_textbox = ctk.CTkTextbox(self.results_frame, wrap="word", state="disabled", font=('Courier New', 12))
        self.result_textbox.pack(fill="both", expand=True, padx=20, pady=20)

        self._create_port_scan_frame()
        self._create_packet_frame()
        self._create_bandwidth_monitor_frame()
        self._create_network_config_frame()
        
        self.packet_analyzer_instance = None
        
    # Definition of methods comes BEFORE they're called/referenced
    def show_notification(self, message):
        """Display a notification when bandwidth threshold is exceeded"""
        try:
            self.result_textbox.configure(state="normal")
            self.result_textbox.delete("1.0", "end")
            self.result_textbox.insert("end", f"⚠️ ALERT: {message} ⚠️\n\n")
            self.result_textbox.configure(state="disabled")
            
            messagebox.showwarning("Bandwidth Alert", message)
        except Exception as e:
            print(f"Error showing notification: {str(e)}")
            
    def frame_generation(self, choice):
        """Handle port scan frame generation based on selected option"""
        if choice == 'Manual':
            self.port_range_frame.grid()
        else:  # Automatic
            self.port_range_frame.grid_remove()
            self.start_port_scan(automatic=True)
            
    def _create_label_and_entry(self, text, row, placeholder):
        ctk.CTkLabel(self, text=text, font=('Arial', 14)).grid(row=row, column=0, sticky="w", padx=10, pady=5)
        entry = ctk.CTkEntry(self, placeholder_text=placeholder)
        entry.grid(row=row, column=1, padx=10, pady=5)
        if row == 1:  
            self.domain = entry

    def _create_label_and_option_menu(self, text, values, row, command=None):
        ctk.CTkLabel(self, text=text, font=("Arial", 14)).grid(row=row, column=0, sticky="w", padx=10, pady=5)
        
        option_menu = ctk.CTkOptionMenu(
            self, values=values, command=command, width=200
        )
        option_menu.grid(row=row, column=1, padx=10, pady=5)
        
        return option_menu

    def _create_port_scan_frame(self):
        self.portscan_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.portscan_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.portscan_frame.grid_remove()

        ctk.CTkLabel(self.portscan_frame, text='Select Port Scan Type:').grid(row=0, column=0, padx=10, pady=5)
        self.portscan_option_select = ctk.CTkOptionMenu(
            self.portscan_frame, values=['Automatic', 'Manual'], command=self.frame_generation
        )
        self.portscan_option_select.grid(row=0, column=1, padx=10, pady=5)

        self._create_port_range_frame()

    def _create_port_range_frame(self):
        self.port_range_frame = ctk.CTkFrame(self.portscan_frame, border_width=1, corner_radius=8)
        self.port_range_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.port_range_frame.grid_remove()

        ctk.CTkLabel(self.port_range_frame, text='Enter Start and End Ports:').grid(
            row=0, column=0, columnspan=2, padx=10, pady=5
        )
        self.start_port = ctk.CTkEntry(self.port_range_frame, placeholder_text='Start Port')
        self.start_port.grid(row=1, column=0, padx=10, pady=5)
        self.end_port = ctk.CTkEntry(self.port_range_frame, placeholder_text='End Port')
        self.end_port.grid(row=1, column=1, padx=10, pady=5)

        self.scan_btn = ctk.CTkButton(
            self.port_range_frame, text='Start Scan', command=self.start_port_scan, width=100
        )
        self.scan_btn.grid(row=2, column=0, columnspan=2, pady=10)

    def _create_packet_frame(self):
        self.packet_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.packet_frame.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.packet_frame.grid_remove()

    def _create_bandwidth_monitor_frame(self):
        self.bandwidth_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.bandwidth_frame.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.bandwidth_frame.grid_remove()

        self.bandwidth_ui = BandwidthMonitorUI(self.bandwidth_frame, self.bandwidth_monitor)
        self.bandwidth_ui.pack(fill="both", expand=True)

    # Add this method to create the network config frame
    def _create_network_config_frame(self):
        self.network_config_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.network_config_frame.grid(row=8, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.network_config_frame.grid_remove()  # Hide initially
        
        # Create the network config app inside this frame
        self.network_config_app = NetworkConfigApp(self.network_config_frame)

    # Update the operation_selected method
    def operation_selected(self, operation):
        """Handle when operation is selected from dropdown."""
        # Hide all frames first
        frames = [
            self.portscan_frame, self.packet_frame, self.traceroute_frame,
            self.bandwidth_frame, self.network_config_frame
        ]
        for frame in frames:
            frame.grid_remove()
            
        # Update placeholder text based on operation
        if operation == 'Ping' or operation == 'Port Scan' or operation == 'Trace Route':
            self.domain.configure(placeholder_text="e.g., google.com or 192.168.1.1")
        elif operation == 'Network Config':
            self.domain.configure(placeholder_text="Not needed for Network Config")
        else:
            self.domain.configure(placeholder_text="Enter target information if needed")

    def domain_entry(self):
        """Handle the operation selected by the user."""
        self.target = self.domain.get()
        operation = self.operation.get()

        self.result_textbox.configure(state="normal")
        self.result_textbox.delete("1.0", "end")  
        self.result_textbox.configure(state="disabled")

        if operation == 'Ping':
            self.start_ping()
        elif operation == 'Port Scan':
            self.portscan_frame.grid()
        elif operation == 'Packet Analysis':
            self.start_packet_analysis()
        elif operation == 'Trace Route':
            self.start_trace()
        elif operation == 'ARP Spoof':
            self.launch_arp_spoof()
        elif operation == 'Firewall':
            self.launch_firewall()
        elif operation == 'Bandwidth Monitor':
            self.bandwidth_frame.grid()
        elif operation == 'Network Config':
            self.network_config_frame.grid()
            self.append_result("Network Configuration Tool activated. Use the tabs above to access different network tools.")

    def start_ping(self):
        result = ping_function(self.target)
        self.append_result(result)

    def start_port_scan(self, automatic=False):
        try:
            if automatic:
                result = portscannez(self.target, 0, 10000)  
            else:
                start_port = int(self.start_port.get())
                end_port = int(self.end_port.get())
                result = portscannez(self.target, start_port, end_port)

            result_str = "\n".join([f"Port {port}: {protocols}" for port, protocols in result.items()])
            self.append_result(result_str)
        except ValueError:
            self.append_result("Invalid port range. Please enter valid numbers.")

    def start_packet_analysis(self):
        """Launch packet analysis visualization"""
        try:
            # Make the packet frame visible
            self.packet_frame.grid()
            
            # Check if we already have an instance
            if self.packet_analyzer_instance is None:
                self.packet_analyzer_instance = PacketAnalyzer(self.packet_frame)
                self.append_result("Packet Analysis tool initialized.\n\nThe packet analyzer is now monitoring network traffic.")
            else:
                # If we already have an instance, just make sure it's visible and running
                self.packet_analyzer_instance.refresh_interface()
                self.append_result("Packet Analysis tool resumed.")
                
        except Exception as e:
            self.append_result(f"Error starting packet analyzer: {str(e)}")
            # Print full exception details for debugging
            import traceback
            print(f"Packet analyzer error details: {traceback.format_exc()}")

    def start_trace(self):
        """Launch the traceroute visualization with improved display handling"""
        try:
            if not self.target:
                self.append_result("Please enter a valid domain or IP address.")
                return
                
            # Create a new window for the traceroute visualization
            trace_window = ctk.CTkToplevel(self)
            trace_window.title(f"Traceroute to {self.target}")
            trace_window.geometry("800x600")
            
            # Create a frame for progress indicators
            progress_frame = ctk.CTkFrame(trace_window)
            progress_frame.pack(fill="x", padx=10, pady=10)
            
            # Add a progress label with more detailed information
            progress_label = ctk.CTkLabel(
                progress_frame, 
                text=f"Tracing route to {self.target}...",
                font=("Helvetica", 14, "bold")
            )
            progress_label.pack(pady=(5, 0))
            
            # Add a more detailed status label
            status_label = ctk.CTkLabel(
                progress_frame,
                text="Initializing traceroute...",
                font=("Helvetica", 12)
            )
            status_label.pack(pady=(0, 5))
            
            # Add a progress bar
            progress_bar = ctk.CTkProgressBar(progress_frame, width=700)
            progress_bar.pack(pady=5)
            progress_bar.set(0)  # Initialize at 0
            
            # Create a dedicated visualization frame
            vis_frame = ctk.CTkFrame(trace_window)
            vis_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Add a cancel button
            cancel_button = ctk.CTkButton(
                progress_frame,
                text="Cancel Traceroute",
                command=lambda: [
                    cancel_trace.set(),
                    trace_window.destroy(),
                    self.append_result("Traceroute cancelled by user.")
                ]
            )
            cancel_button.pack(pady=5)
            
            # Force window update to show the progress elements
            trace_window.update()
            
            # Create a shared variable for cancellation
            cancel_trace = threading.Event()
            
            # Create the traceroute visualizer in a separate thread with progress updates
            def run_traceroute():
                try:
                    # Important: Create the visualization directly inside the vis_frame
                    # and force the parent window to wait for it to complete
                    tracer = TracerouteVisualizerApp(vis_frame, target_ip=self.target)
                    tracer.pack(fill="both", expand=True)  # Make sure the tracer is visible
                    
                    # When complete, update UI
                    if not cancel_trace.is_set():
                        progress_bar.set(1.0)  # Set to 100%
                        status_label.configure(text="Traceroute complete!")
                        progress_label.configure(text=f"Trace to {self.target} completed successfully")
                        cancel_button.configure(text="Close Window")
                except Exception as e:
                    if not cancel_trace.is_set():
                        # Show error in the trace window
                        progress_bar.set(0)
                        status_label.configure(text=f"Error: {str(e)}", text_color="red")
                        progress_label.configure(text="Traceroute failed", text_color="red")
                        print(f"Traceroute error: {str(e)}")
            
            # Start traceroute in a separate thread to prevent freezing the UI
            trace_thread = threading.Thread(target=run_traceroute, daemon=True)
            trace_thread.start()
            
            # Simulate progress updates (since we removed the actual progress callback)
            def simulate_progress():
                if cancel_trace.is_set() or not trace_window.winfo_exists():
                    return
                    
                # Update progress bar with simulated progress
                current_progress = progress_bar.get()
                if current_progress < 1.0:
                    new_progress = min(current_progress + 0.02, 0.95)  # Max at 95% until complete
                    progress_bar.set(new_progress)
                    status_label.configure(text=f"Tracing route... approximately {int(new_progress*100)}% complete")
                    
                # Schedule next update
                trace_window.after(1000, simulate_progress)
                
            # Start progress simulation
            trace_window.after(1000, simulate_progress)
            
            # Display a message in the main window
            self.append_result(
                f"Traceroute to {self.target} launched in a new window.\n\n"
                "The visualization will appear when the trace completes.\n"
                "This can take several minutes for distant targets.\n\n"
                "You can continue using other tools while the trace runs."
            )
                
        except Exception as e:
            self.append_result(f"Error starting traceroute: {str(e)}")

    def append_result(self, text):
        self.result_textbox.configure(state="normal")
        self.result_textbox.delete("1.0", "end")  
        self.result_textbox.insert("end", text + "\n")
        self.result_textbox.configure(state="disabled")

    def launch_arp_spoof(self):
        """Launch ARP Spoofing tool in a separate window"""
        if not hasattr(self, 'arp_spoof_window') or self.arp_spoof_window is None or not self.arp_spoof_window.winfo_exists():
            import os
            import sys
            import subprocess
            
            try:
                startupinfo = None
                if os.name == 'nt':  # Windows
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
                # Check if we're running in a bundled application
                if getattr(sys, 'frozen', False):
                    # Running as compiled exe
                    # Create a toplevel window instead of launching a new process
                    self.arp_spoof_window = ctk.CTkToplevel(self)
                    self.arp_spoof_window.title("ARP Spoofing Tool")
                    self.arp_spoof_window.geometry("500x400")
                    
                    # Create the ARP spoofing app directly in this window
                    arp_app = arp.ARP_SpoofingApp()
                    arp_app.root = self.arp_spoof_window
                    arp_app.setup_gui()
                    
                    self.append_result("ARP Spoofing tool launched in a new window.")
                else:
                    # Running as Python script - can use subprocess
                    arp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arp.py")
                    subprocess.Popen([sys.executable, arp_path], startupinfo=startupinfo)
                    self.append_result("ARP Spoofing tool launched in a new window.")
            except Exception as e:
                self.append_result(f"Error launching ARP Spoofing tool: {str(e)}")
        else:
            self.arp_spoof_window.lift()
            self.append_result("ARP Spoofing tool window is already open.")

    def launch_firewall(self):
        """Launch Firewall tool in a separate window"""
        if not hasattr(self, 'firewall_window') or self.firewall_window is None or not self.firewall_window.winfo_exists():
            import os
            import sys
            import subprocess
            import json
            
            try:
                startupinfo = None
                if os.name == 'nt':  # Windows
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
                # Check if we're running in a bundled application
                if getattr(sys, 'frozen', False):
                    # Running as compiled exe
                    # Create a toplevel window instead of launching a new process
                    self.firewall_window = ctk.CTkToplevel(self)
                    self.firewall_window.title("Firewall Control")
                    self.firewall_window.geometry("600x500")  # Larger window for more content
                    
                    # IMPORTANT: Create a regular frame instead of trying to use FirewallApp
                    firewall_frame = ctk.CTkFrame(self.firewall_window)
                    firewall_frame.pack(fill="both", expand=True)
                    
                    # Create the tabs and UI directly without FirewallApp
                    tabview = ctk.CTkTabview(firewall_frame)
                    tabview.pack(padx=10, pady=10, fill="both", expand=True)
                    
                    # Create tabs - add Current Rules tab
                    tabview.add("IP Blocking")
                    tabview.add("URL Blocking")
                    tabview.add("Current Rules")
                    
                    # URL rules storage file path
                    url_rules_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "url_rules.json")
                    
                    # Setup IP Blocking tab content
                    ip_frame = tabview.tab("IP Blocking")
                    # IP address entry
                    ip_label = ctk.CTkLabel(ip_frame, text="IP Address:")
                    ip_label.pack(pady=5)
                    
                    ip_entry = ctk.CTkEntry(ip_frame, width=300)
                    ip_entry.pack(pady=5)
                    
                    # Rule name entry
                    rule_name_label = ctk.CTkLabel(ip_frame, text="Rule Name:")
                    rule_name_label.pack(pady=5)
                    
                    rule_name_entry = ctk.CTkEntry(ip_frame, width=300)
                    rule_name_entry.pack(pady=5)
                    
                    # Button frame
                    button_frame = ctk.CTkFrame(ip_frame)
                    button_frame.pack(pady=10)
                    
                    # Function to get current firewall rules
                    def get_firewall_rules():
                        try:
                            result = subprocess.check_output(
                                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                                universal_newlines=True,
                                startupinfo=startupinfo
                            )
                            return result
                        except Exception as e:
                            return f"Error retrieving rules: {str(e)}"
                    
                    # Function to save URL rules
                    def save_url_rule(url, rule_name, ip_address):
                        try:
                            # Load existing rules
                            url_rules = {}
                            if os.path.exists(url_rules_file):
                                with open(url_rules_file, 'r') as f:
                                    url_rules = json.load(f)
                            
                            # Add new rule
                            url_rules[url] = {"rule_name": rule_name, "ip": ip_address}
                            
                            # Save rules
                            with open(url_rules_file, 'w') as f:
                                json.dump(url_rules, f, indent=2)
                        except Exception as e:
                            print(f"Error saving URL rule: {str(e)}")
                    
                    # Function to load URL rules
                    def load_url_rules():
                        try:
                            if os.path.exists(url_rules_file):
                                with open(url_rules_file, 'r') as f:
                                    return json.load(f)
                            return {}
                        except Exception as e:
                            print(f"Error loading URL rules: {str(e)}")
                            return {}
                    
                    # Function to remove URL rule
                    def remove_url_rule(url=None, rule_name=None):
                        try:
                            if not os.path.exists(url_rules_file):
                                return
                            
                            url_rules = load_url_rules()
                            
                            # Remove by URL
                            if url and url in url_rules:
                                del url_rules[url]
                            
                            # Remove by rule name
                            if rule_name:
                                urls_to_remove = []
                                for url, data in url_rules.items():
                                    if isinstance(data, dict) and data.get("rule_name") == rule_name:
                                        urls_to_remove.append(url)
                            
                                for url in urls_to_remove:
                                    del url_rules[url]
                            
                            # Save updated rules
                            with open(url_rules_file, 'w') as f:
                                json.dump(url_rules, f, indent=2)
                        except Exception as e:
                            print(f"Error removing URL rule: {str(e)}")
                    
                    # Define the functions first
                    def block_ip(ip, rule_name):
                        if ip and rule_name:
                            try:
                                subprocess.run([
                                    "netsh", "advfirewall", "firewall", "add", "rule", 
                                    f"name={rule_name}", "dir=in", "action=block", 
                                    f"remoteip={ip}"
                                ], check=True)
                                messagebox.showinfo("Success", f"IP {ip} has been blocked with rule {rule_name}.")
                                update_rules_display()  # Update the rules display
                            except subprocess.CalledProcessError as e:
                                messagebox.showerror("Error", f"Failed to block IP {ip}: {str(e)}")
                        else:
                            messagebox.showwarning("Input Error", "Please enter a valid IP address and rule name.")
                    
                    def unblock_ip(rule_name):
                        if rule_name:
                            try:
                                subprocess.run([
                                    "netsh", "advfirewall", "firewall", "delete", "rule", 
                                    f"name={rule_name}"
                                ], check=True)
                                messagebox.showinfo("Success", f"Rule {rule_name} has been deleted.")
                                update_rules_display()  # Update the rules display
                            except subprocess.CalledProcessError as e:
                                messagebox.showerror("Error", f"Failed to delete rule {rule_name}: {str(e)}")
                        else:
                            messagebox.showwarning("Input Error", "Please enter a valid rule name.")
                    
                    # Block button
                    block_button = ctk.CTkButton(
                        button_frame, 
                        text="Block IP", 
                        command=lambda: block_ip(ip_entry.get(), rule_name_entry.get())
                    )
                    block_button.pack(side="left", padx=5)
                    
                    # Unblock button
                    unblock_button = ctk.CTkButton(
                        button_frame, 
                        text="Unblock IP", 
                        command=lambda: unblock_ip(rule_name_entry.get())
                    )
                    unblock_button.pack(side="left", padx=5)
                    
                    # Setup URL Blocking tab content
                    url_frame = tabview.tab("URL Blocking")
                    
                    # URL entry
                    url_label = ctk.CTkLabel(url_frame, text="URL to Block:")
                    url_label.pack(pady=5)
                    
                    url_entry = ctk.CTkEntry(url_frame, width=300)
                    url_entry.pack(pady=5)
                    
                    # Rule name entry for URL
                    url_rule_name_label = ctk.CTkLabel(url_frame, text="Rule Name:")
                    url_rule_name_label.pack(pady=5)
                    
                    url_rule_name_entry = ctk.CTkEntry(url_frame, width=300)
                    url_rule_name_entry.pack(pady=5)
                    
                    # Button frame for URL
                    url_button_frame = ctk.CTkFrame(url_frame)
                    url_button_frame.pack(pady=10)
                    
                    # URL rules display
                    url_rules_frame = ctk.CTkFrame(url_frame)
                    url_rules_frame.pack(fill="both", expand=True, pady=10)
                    
                    url_rules_label = ctk.CTkLabel(url_rules_frame, text="Blocked URLs:")
                    url_rules_label.pack(pady=5)
                    
                    url_rules_text = ctk.CTkTextbox(url_rules_frame, height=120)
                    url_rules_text.pack(fill="both", expand=True, padx=5, pady=5)
                    
                    def display_url_rules():
                        url_rules = load_url_rules()
                        url_rules_text.configure(state="normal")
                        url_rules_text.delete("1.0", "end")
                        
                        if url_rules:
                            for url, data in url_rules.items():
                                if isinstance(data, dict):
                                    rule_name = data.get("rule_name", "Unknown")
                                    ip = data.get("ip", "Unknown")
                                    url_rules_text.insert("end", f"URL: {url}\nRule: {rule_name}\nIP: {ip}\n\n")
                                else:
                                    url_rules_text.insert("end", f"URL: {url}\nRule: {data}\n\n")
                        else:
                            url_rules_text.insert("end", "No URL rules found.")
                        
                        url_rules_text.configure(state="disabled")
                    
                    def block_url(url, rule_name):
                        if url and rule_name:
                            try:
                                # Extract domain and try to resolve IP
                                if url.startswith("http://"):
                                    domain = url[7:]
                                elif url.startswith("https://"):
                                    domain = url[8:]
                                else:
                                    domain = url
                                
                                domain = domain.split("/")[0]
                                
                                try:
                                    import socket
                                    ip_address = socket.gethostbyname(domain)
                                    subprocess.run([
                                        "netsh", "advfirewall", "firewall", "add", "rule", 
                                        f"name={rule_name}", "dir=in", "action=block", 
                                        f"remoteip={ip_address}"
                                    ], check=True)
                                    
                                    # Save URL rule
                                    save_url_rule(url, rule_name, ip_address)
                                    display_url_rules()  # Update URL rules display
                                    update_rules_display()  # Update firewall rules display
                                    
                                    messagebox.showinfo("Success", f"URL {url} (IP: {ip_address}) has been blocked.")
                                except Exception as inner_e:
                                    messagebox.showerror("Error", f"Could not resolve domain {domain}: {str(inner_e)}")
                            except Exception as e:
                                messagebox.showerror("Error", f"Failed to block URL {url}: {str(e)}")
                        else:
                            messagebox.showwarning("Input Error", "Please enter a valid URL and rule name.")
                    
                    def unblock_url(rule_name):
                        if rule_name:
                            try:
                                subprocess.run([
                                    "netsh", "advfirewall", "firewall", "delete", "rule", 
                                    f"name={rule_name}"
                                ], check=True)
                                
                                # Remove from saved rules
                                remove_url_rule(rule_name=rule_name)
                                display_url_rules()  # Update URL rules display
                                update_rules_display()  # Update firewall rules display
                                
                                messagebox.showinfo("Success", f"Rule {rule_name} has been deleted.")
                            except subprocess.CalledProcessError as e:
                                messagebox.showerror("Error", f"Failed to delete rule {rule_name}: {str(e)}")
                        else:
                            messagebox.showwarning("Input Error", "Please enter a valid rule name.")
                    
                    # Block URL button
                    block_url_button = ctk.CTkButton(
                        url_button_frame, 
                        text="Block URL", 
                        command=lambda: block_url(url_entry.get(), url_rule_name_entry.get())
                    )
                    block_url_button.pack(side="left", padx=5)
                    
                    # Unblock URL button
                    unblock_url_button = ctk.CTkButton(
                        url_button_frame, 
                        text="Unblock URL", 
                        command=lambda: unblock_url(url_rule_name_entry.get())
                    )
                    unblock_url_button.pack(side="left", padx=5)
                    
                    # Button to show URL rules
                    show_url_rules_button = ctk.CTkButton(
                        url_rules_frame,
                        text="Show Blocked URLs",
                        command=display_url_rules
                    )
                    show_url_rules_button.pack(pady=5)
                    
                    # Setup Current Rules tab content
                    rules_frame = tabview.tab("Current Rules")
                    
                    rules_label = ctk.CTkLabel(rules_frame, text="Current Firewall Rules:")
                    rules_label.pack(pady=5)
                    
                    # Add filter capabilities
                    filter_frame = ctk.CTkFrame(rules_frame)
                    filter_frame.pack(fill="x", pady=5)
                    
                    filter_label = ctk.CTkLabel(filter_frame, text="Filter:")
                    filter_label.pack(side="left", padx=5)
                    
                    filter_entry = ctk.CTkEntry(filter_frame, width=200)
                    filter_entry.pack(side="left", padx=5)
                    
                    # Rules display textbox
                    rules_text = ctk.CTkTextbox(rules_frame, height=300)
                    rules_text.pack(fill="both", expand=True, padx=5, pady=5)
                    
                    def update_rules_display():
                        filter_value = filter_entry.get()
                        if filter_value:
                            rules = get_firewall_rules_filtered(filter_value)
                        else:
                            rules = get_firewall_rules()
                        
                        rules_text.configure(state="normal")
                        rules_text.delete("1.0", "end")
                        rules_text.insert("end", rules)
                        rules_text.configure(state="disabled")
                    
                    def get_firewall_rules_filtered(filter_text):
                        try:
                            result = subprocess.check_output(
                                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={filter_text}"],
                                universal_newlines=True,
                                startupinfo=startupinfo
                            )
                            return result
                        except Exception as e:
                            return f"Error retrieving rules with filter '{filter_text}': {str(e)}"
                    
                    # Refresh button with filter capability
                    refresh_button = ctk.CTkButton(
                        filter_frame,
                        text="Refresh Rules",
                        command=update_rules_display
                    )
                    refresh_button.pack(side="left", padx=5)
                    
                    # Initial load of rules and URL data
                    update_rules_display()
                    display_url_rules()
                    
                    self.append_result("Firewall tool launched in a new window.")
                else:
                    # Running as Python script - can use subprocess
                    firewall_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall.py")
                    subprocess.Popen([sys.executable, firewall_path], startupinfo=startupinfo)
                    self.append_result("Firewall tool launched in a new window.")
            except Exception as e:
                self.append_result(f"Error launching firewall: {str(e)}")
        else:
            self.firewall_window.lift()
            self.append_result("Firewall tool window is already open.")

    def on_close(self):
        """Clean up before closing"""
        self.bandwidth_monitor.stop()
        self.destroy()

if __name__ == '__main__':
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)  
    app.mainloop()