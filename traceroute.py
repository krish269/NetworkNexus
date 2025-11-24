import customtkinter as ctk
import subprocess
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import re
import threading

class TracerouteVisualizerApp(ctk.CTkFrame):
    def __init__(self, parent, target_ip, progress_callback=None):
        super().__init__(parent)  # Initialize as a frame within the parent widget
        self.target_ip = target_ip  # Store the target IP
        self.progress_callback = progress_callback
        self.setup_ui()
        
        # Automatically start the traceroute after initialization
        # Use after() to give the UI time to render first
        self.after(100, self.start_traceroute)

    def setup_ui(self):
        # UI components inside the traceroute frame
        label_title = ctk.CTkLabel(self, text="Traceroute Visualization", font=("Arial", 20, "bold"))
        label_title.pack(pady=10)

        button_traceroute = ctk.CTkButton(self, text="Start Traceroute", command=self.start_traceroute)
        button_traceroute.pack(pady=10)

    def run_nmap_traceroute(self, target_ip):
        try:
            result = subprocess.run(
                ["nmap", "-sn", "--traceroute", target_ip],
                capture_output=True, text=True, check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error: {e}"

    def parse_traceroute_output(self, output):
        hop_pattern = re.compile(r"([\d.]+)\s+ms\s+([\d.]+)")
        hops = [(match.group(1), match.group(2)) for match in hop_pattern.finditer(output)]
        return hops

    def visualize_topology(self, hops):
        G = nx.DiGraph()
        previous_node = "localhost"
        G.add_node(previous_node)

        for rtt, ip in hops:
            G.add_node(ip)
            G.add_edge(previous_node, ip)
            previous_node = ip

        fig, ax = plt.subplots(figsize=(6, 6))
        nx.draw(G, with_labels=True, node_color='lightblue', arrows=True, ax=ax)
        plt.title("Traceroute Visualization")
        return fig

    def start_traceroute(self):
        output = self.run_nmap_traceroute(self.target_ip)
        hops = self.parse_traceroute_output(output)
        fig = self.visualize_topology(hops)

        canvas = FigureCanvasTkAgg(fig, master=self)
        canvas.draw()
        canvas.get_tk_widget().pack(pady=10)

    def perform_traceroute(self):
        # In your traceroute loop
        for hop_number, results in enumerate(traceroute, 1):
            # Process hop
            
            # If progress callback is provided, call it
            if self.progress_callback:
                continue_trace = self.progress_callback(hop_number, hop_ip, rtt)
                if not continue_trace:
                    break  # Allow cancellation

    def start_trace(self):
        """Launch the traceroute visualization with progress updates"""
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
            
            # Add a cancel button
            cancel_button = ctk.CTkButton(
                progress_frame,
                text="Cancel Traceroute",
                command=lambda: [
                    trace_window.destroy(),
                    self.append_result("Traceroute cancelled by user.")
                ]
            )
            cancel_button.pack(pady=5)
            
            # Create content frame where traceroute visualization will appear
            content_frame = ctk.CTkFrame(trace_window)
            content_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Force window update to show the progress elements
            trace_window.update()
            
            # Create a shared variable for cancellation
            cancel_trace = threading.Event()
            
            # Create the traceroute visualizer in a separate thread with progress updates
            def run_traceroute():
                try:
                    # Estimate max hops (typical internet routes are 15-30 hops)
                    max_hops = 30
                    
                    # Modified: Create TracerouteVisualizerApp instance first
                    tracer = TracerouteVisualizerApp(
                        content_frame,  # Use content_frame as the parent
                        target_ip=self.target,
                        progress_callback=lambda hop_num, hop_ip, hop_time: update_progress(hop_num, hop_ip, hop_time)
                    )
                    
                    # Custom progress update function
                    def update_progress(current_hop, hop_ip, hop_time):
                        if cancel_trace.is_set():
                            return False  # Signal to stop tracing
                            
                        # Update progress bar
                        progress_value = min(current_hop / max_hops, 1.0)
                        progress_bar.set(progress_value)
                        
                        # Update status text
                        status_label.configure(text=f"Discovered hop {current_hop}: {hop_ip} ({hop_time}ms)")
                        
                        # Update window
                        trace_window.update()
                        return True  # Continue tracing
                    
                    # Start the traceroute (this should trigger the visualization)
                    tracer.start_traceroute()
                    
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
            
            # Start traceroute in a separate thread to prevent freezing the UI
            trace_thread = threading.Thread(target=run_traceroute, daemon=True)
            trace_thread.start()
            
            # Display a message in the main window
            self.append_result(
                f"Traceroute to {self.target} launched in a new window.\n\n"
                "Progress updates will appear as the trace continues.\n"
                "This can take several minutes for distant targets.\n\n"
                "You can continue using other tools while the trace runs."
            )
            
        except Exception as e:
            self.append_result(f"Error starting traceroute: {str(e)}")


if __name__ == "__main__":
    app = TracerouteVisualizerApp()
    app.mainloop()
