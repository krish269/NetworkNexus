import customtkinter as ctk
import psutil
import time
from datetime import datetime
import threading
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class NetworkBandwidthMonitor:
    def __init__(self):
        # Set appearance mode and theme
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        
        self.root = ctk.CTk()
        self.root.title("Network Bandwidth Monitor")
        self.root.geometry("700x600")  # Increased size for better CTk display
        
        # Store previous measurements
        self.prev_io = None
        self.flood_threshold = ctk.DoubleVar(value=1.0)  # Default 1 MB/s for easier testing
        self.current_threshold = 1.0  # Track the active threshold
        self.alert_active = False  # Track if an alert is active
        
        # Setup GUI elements
        self.setup_gui()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.monitor_thread.start()

    def setup_gui(self):
        # Create main frames
        self.stats_frame = ctk.CTkFrame(self.root)
        self.stats_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Add labels for statistics
        stats_container = ctk.CTkFrame(self.stats_frame)
        stats_container.pack(fill="x", padx=10, pady=10)
        
        self.upload_label = ctk.CTkLabel(stats_container, text="Upload Speed: 0 KB/s", 
                                      font=("Helvetica", 12))
        self.download_label = ctk.CTkLabel(stats_container, text="Download Speed: 0 KB/s", 
                                        font=("Helvetica", 12))
        self.total_label = ctk.CTkLabel(stats_container, text="Total Speed: 0 KB/s", 
                                      font=("Helvetica", 12))
        
        self.upload_label.pack(pady=5)
        self.download_label.pack(pady=5)
        self.total_label.pack(pady=5)

        # Flood detection status
        self.flood_status = ctk.CTkLabel(stats_container, text="Status: Normal", 
                                      text_color="green", font=("Helvetica", 14, "bold"))
        self.flood_status.pack(pady=10)

        # Threshold controls frame
        self.threshold_frame = ctk.CTkFrame(self.stats_frame)
        self.threshold_frame.pack(fill="x", padx=10, pady=10)

        # Title for threshold settings
        threshold_title = ctk.CTkLabel(self.threshold_frame, text="Flood Detection Settings", 
                                    font=("Helvetica", 12, "bold"))
        threshold_title.pack(anchor="w", padx=5, pady=5)
        
        # Threshold controls - Using a sub-frame for controls
        controls_frame = ctk.CTkFrame(self.threshold_frame)
        controls_frame.pack(fill="x", padx=5, pady=5)
        
        # Threshold adjustment controls
        threshold_label = ctk.CTkLabel(controls_frame, text="Threshold (MB/s):")
        threshold_label.pack(side="left", padx=5)
        
        threshold_entry = ctk.CTkEntry(controls_frame, width=80, textvariable=self.flood_threshold)
        threshold_entry.pack(side="left", padx=5)
        
        # Add Update button for threshold
        update_button = ctk.CTkButton(
            controls_frame,
            text="Update Threshold",
            command=self.update_threshold
        )
        update_button.pack(side="left", padx=5)
        
        reset_button = ctk.CTkButton(
            controls_frame,
            text="Reset to Default",
            command=lambda: [self.flood_threshold.set(1.0), self.update_threshold()]
        )
        reset_button.pack(side="left", padx=5)

        # Current threshold display
        self.threshold_label = ctk.CTkLabel(self.threshold_frame, 
                                         text=f"Current Threshold: {self.current_threshold} MB/s")
        self.threshold_label.pack(anchor="w", padx=5, pady=5)

        # Graph frame for future implementation
        graph_frame = ctk.CTkFrame(self.stats_frame)
        graph_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create matplotlib figure for network traffic visualization
        self.fig = Figure(figsize=(6, 3), dpi=100)
        self.fig.patch.set_facecolor('#E4E4E4')  # Match background
        self.plot = self.fig.add_subplot(111)
        self.plot.set_title('Network Traffic')
        self.plot.set_xlabel('Time (s)')
        self.plot.set_ylabel('Speed (KB/s)')
        self.plot.grid(True)
        
        # Create canvas to display the figure
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)
        
        # Store data for graph
        self.time_data = []
        self.upload_data = []
        self.download_data = []
        self.total_data = []
        self.max_data_points = 60  # 1 minute of data

        # Log area
        log_frame = ctk.CTkFrame(self.stats_frame)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        log_title = ctk.CTkLabel(log_frame, text="Event Log", font=("Helvetica", 12, "bold"))
        log_title.pack(anchor="w", padx=5, pady=5)
        
        # Text box for logs with scrollbar
        self.log_text = ctk.CTkTextbox(log_frame, height=150)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Log initial setup
        self.log(f"Network monitoring started. Initial threshold set to {self.current_threshold} MB/s")

    def log(self, message):
        """Add a timestamped message to the log"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {message}"
        self.log_text.insert("end", log_message + "\n")
        self.log_text.see("end")

    def update_threshold(self):
        """Update the active threshold from the entry field"""
        try:
            new_threshold = float(self.flood_threshold.get())
            if new_threshold <= 0:
                raise ValueError("Threshold must be positive")
                
            self.current_threshold = new_threshold
            self.threshold_label.configure(text=f"Current Threshold: {new_threshold} MB/s")
            
            # Log the threshold change
            self.log(f"Threshold updated to {new_threshold} MB/s")
            
            # Reset status if it was in alert mode
            if self.alert_active:
                self.alert_active = False
                self.flood_status.configure(text="Status: Normal", text_color="green")
                self.log("Alert status reset to normal")
            
        except ValueError as e:
            self.log(f"Error: {str(e)}")

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
        while True:
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
                    
                    # Update GUI with current values
                    self.root.after(0, lambda u=upload_bytes, d=download_bytes, t=total_bytes: 
                                   self.update_gui(u, d, t))
                    
                    # Check if we're exceeding threshold
                    if total_mb > self.current_threshold and not self.alert_active:
                        self.root.after(0, lambda s=total_mb: self.trigger_flood_alert(s))
                    elif total_mb <= self.current_threshold and self.alert_active:
                        self.root.after(0, self.clear_alert)
                
                self.prev_io = io
            except Exception as e:
                self.root.after(0, lambda e=e: self.log(f"Error in monitoring: {str(e)}"))
            
            time.sleep(1)

    def update_gui(self, upload_bytes, download_bytes, total_bytes):
        """Update GUI elements safely"""
        # Update text labels
        self.upload_label.configure(text=f"Upload Speed: {self.convert_bytes(upload_bytes)}")
        self.download_label.configure(text=f"Download Speed: {self.convert_bytes(download_bytes)}")
        self.total_label.configure(text=f"Total Speed: {self.convert_bytes(total_bytes)}")
        
        # Update graph
        self.plot.clear()
        self.plot.plot(self.time_data, self.upload_data, 'g-', label='Upload')
        self.plot.plot(self.time_data, self.download_data, 'b-', label='Download')
        self.plot.plot(self.time_data, self.total_data, 'r-', label='Total')
        
        # Update graph labels and appearance
        self.plot.set_title('Network Traffic')
        self.plot.set_xlabel('Time (s)')
        self.plot.set_ylabel('Speed (KB/s)')
        self.plot.grid(True)
        
        # Add legend with proper position
        self.plot.legend(loc='upper left')
        
        # Set y-axis limits with some headroom
        if self.total_data:
            max_value = max(max(self.total_data) if self.total_data else 0, 1)  # Avoid divisions by zero
            self.plot.set_ylim([0, max_value * 1.2])  # 20% headroom
        
        # Draw the updated plot
        self.canvas.draw()

    def trigger_flood_alert(self, speed_mb):
        """Handle flood detection alert"""
        self.alert_active = True
        self.flood_status.configure(text="Status: FLOOD DETECTED!", text_color="red")
        self.log(f"Flood detected! Total speed: {speed_mb:.2f} MB/s exceeds threshold of {self.current_threshold} MB/s")

    def clear_alert(self):
        """Clear flood alert when traffic returns to normal"""
        self.alert_active = False
        self.flood_status.configure(text="Status: Normal", text_color="green")
        self.log("Traffic returned to normal levels")

    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = NetworkBandwidthMonitor()
    app.run()