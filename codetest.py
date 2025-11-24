import customtkinter as ctk
from portscanner_copy import ping_function, main, portscannez
from chat import PacketAnalyzer
from traceroute import TracerouteVisualizerApp

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title('Network Nexus Application')
        self.geometry(f'{self.winfo_screenwidth()}x{self.winfo_screenheight()}-10-10')
        self._set_appearance_mode('system')
        self.state('normal')

        # Title
        ctk.CTkLabel(self, text='Welcome to the Network Nexus', font=('Arial', 24, 'bold')).grid(row=0, column=0, columnspan=2, padx=10, pady=20)

        # Domain/IP Entry
        ctk.CTkLabel(self, text='Select Domain/IP Address:', font=('Arial', 14)).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.domain = ctk.CTkEntry(self,placeholder_text='eg: google.com')
        self.domain.grid(row=1, column=1, padx=10, pady=5)

        # Operation Selection
        ctk.CTkLabel(self, text='Select Operation:', font=('Arial', 14)).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.operation = ctk.CTkOptionMenu(
            self, 
            values=['Ping', 'Port Scan', 'Packet Analysis', 'Trace Route'], 
            fg_color='grey', button_color='grey', 
            command=self.operation_selected  # Trigger when operation changes
        )
        self.operation.grid(row=2, column=1, padx=10, pady=5)

        # Results Frame
        self.results_frame = ctk.CTkFrame(self)
        self.results_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=20, sticky="nsew")
        self.result_label = ctk.CTkLabel(self.results_frame, text="", font=('Arial', 12), wraplength=600, justify="left")
        self.result_label.grid(pady=10)

        # Port Scan Frame (Hidden initially)
        self.port_range_frame = self.create_port_scan_frame()
        self.packet_frame = self.create_packet_frame()  # Hidden initially

        # Submit Button
        self.submit_btn = ctk.CTkButton(self, text='Submit', command=self.domain_entry)
        self.submit_btn.grid(row=3, column=0, columnspan=2, pady=20)

    def create_port_scan_frame(self):
        frame = ctk.CTkFrame(self)
        frame.grid(row=5, column=0, columnspan=2, pady=10, padx=10, sticky="nsew")
        frame.grid_remove()

        ctk.CTkLabel(frame, text='Select Port Scan Type').grid(row=0, column=0, padx=10, pady=5)
        self.portscan_option_select = ctk.CTkOptionMenu(frame, values=['Automatic', 'Manual'])
        self.portscan_option_select.grid(row=0, column=1, padx=5, pady=10)

        ctk.CTkLabel(frame, text='Enter start and end ports:').grid(row=1, column=0, columnspan=2, padx=10, pady=5)
        self.start_port = ctk.CTkEntry(frame, placeholder_text='Start Port')
        self.start_port.grid(row=2, column=0, padx=10, pady=5)
        self.end_port = ctk.CTkEntry(frame, placeholder_text='End Port')
        self.end_port.grid(row=2, column=1, padx=10, pady=5)

        self.scan_btn = ctk.CTkButton(frame, text='Start Scan', command=self.start_port_scan)
        self.scan_btn.grid(row=3, column=0, columnspan=2, pady=10)

        return frame

    def create_packet_frame(self):
        frame = ctk.CTkFrame(self)
        frame.grid(row=5, column=0, columnspan=2, pady=10, sticky="nsew")
        frame.grid_remove()
        return frame

    def operation_selected(self, operation):
        # Hide all frames initially
        self.port_range_frame.grid_remove()
        self.packet_frame.grid_remove()

        # Show the appropriate frame based on the selected operation
        if operation == 'Port Scan':
            self.port_range_frame.grid()
        elif operation == 'Packet Analysis':
            self.packet_frame.grid()

    def domain_entry(self):
        self.target = self.domain.get()
        self.operation_descision = self.operation.get()

        # Clear previous results
        self.result_label.configure(text="")

        if self.operation_descision == 'Ping':
            self.start_ping()
        elif self.operation_descision == 'Port Scan':
            self.start_port_scan()
        elif self.operation_descision == 'Packet Analysis':
            self.start_packet_analysis()
        elif self.operation_descision == 'Trace Route':
            self.start_trace(self.target)

    def start_ping(self):
        self.result_label.configure(text=ping_function(self.target))

    def start_trace(self, target):
        traceroute_app = TracerouteVisualizerApp()
        traceroute_app.mainloop()

    def start_port_scan(self):
        try:
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())
            result = portscannez(self.target, start_port, end_port)
            self.result_label.configure(text=result)
        except ValueError:
            self.result_label.configure(text="Invalid port range. Please enter valid numbers.")

    def start_packet_analysis(self):
        self.packet_frame.grid() 
        PacketAnalyzer(self.packet_frame)  

if __name__ == '__main__':
    app = App()
    app.mainloop()
