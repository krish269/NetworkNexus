import customtkinter as ctk
import subprocess
import tkinter as tk
from tkinter import messagebox
import socket

class FirewallApp(ctk.CTk):
    def __init__(self, root=None):
        if root is None:
            super().__init__()
            self.root = self
            # Window setup
            self.title("Firewall Control")
            self.geometry("500x400")
        else:
            self.root = root
        
        # Create GUI elements
        self.create_gui()

    def create_gui(self):
        # Create tabview for IP and URL blocking
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Create tabs
        self.tabview.add("IP Blocking")
        self.tabview.add("URL Blocking")
        
        # Setup IP Blocking tab
        self.create_ip_blocking_tab()
        
        # Setup URL Blocking tab
        self.create_url_blocking_tab()

    def create_ip_blocking_tab(self):
        # Main frame for IP blocking
        ip_frame = self.tabview.tab("IP Blocking")

        # IP address entry
        ip_label = ctk.CTkLabel(ip_frame, text="IP Address:")
        ip_label.pack(pady=5)
        
        self.ip_entry = ctk.CTkEntry(ip_frame, width=300)
        self.ip_entry.pack(pady=5)

        # Rule name entry
        rule_name_label = ctk.CTkLabel(ip_frame, text="Rule Name:")
        rule_name_label.pack(pady=5)
        
        self.rule_name_entry = ctk.CTkEntry(ip_frame, width=300)
        self.rule_name_entry.pack(pady=5)

        # Button frame
        button_frame = ctk.CTkFrame(ip_frame)
        button_frame.pack(pady=10)
        
        # Block button
        block_button = ctk.CTkButton(button_frame, text="Block IP", command=self.block_ip)
        block_button.pack(side="left", padx=5)

        # Unblock button
        unblock_button = ctk.CTkButton(button_frame, text="Unblock IP", command=self.unblock_ip)
        unblock_button.pack(side="left", padx=5)

        # Show rules button
        show_rules_button = ctk.CTkButton(ip_frame, text="Show Firewall Rules", command=self.show_firewall_rules)
        show_rules_button.pack(pady=5)

    def create_url_blocking_tab(self):
        # Main frame for URL blocking
        url_frame = self.tabview.tab("URL Blocking")

        # URL entry
        url_label = ctk.CTkLabel(url_frame, text="URL to Block:")
        url_label.pack(pady=5)
        
        self.url_entry = ctk.CTkEntry(url_frame, width=300)
        self.url_entry.pack(pady=5)

        # Rule name entry for URL
        url_rule_name_label = ctk.CTkLabel(url_frame, text="Rule Name:")
        url_rule_name_label.pack(pady=5)
        
        self.url_rule_name_entry = ctk.CTkEntry(url_frame, width=300)
        self.url_rule_name_entry.pack(pady=5)

        # Information label
        info_label = ctk.CTkLabel(url_frame, text="Note: URL blocking works by resolving domain to IP and blocking it.", 
                                 font=("Arial", 10), text_color="gray")
        info_label.pack(pady=5)

        # Button frame
        url_button_frame = ctk.CTkFrame(url_frame)
        url_button_frame.pack(pady=10)
        
        # Block URL button
        block_url_button = ctk.CTkButton(url_button_frame, text="Block URL", command=self.block_url)
        block_url_button.pack(side="left", padx=5)

        # Unblock URL button
        unblock_url_button = ctk.CTkButton(url_button_frame, text="Unblock URL", command=self.unblock_url)
        unblock_url_button.pack(side="left", padx=5)
        
        # Show URL rules button
        show_url_rules_button = ctk.CTkButton(url_frame, text="Show URL Rules", command=self.show_url_rules)
        show_url_rules_button.pack(pady=5)

    def block_ip(self):
        ip_address = self.ip_entry.get()
        rule_name = self.rule_name_entry.get()
        if ip_address and rule_name:
            try:
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", 
                                f"name={rule_name}", "dir=in", "action=block", 
                                f"remoteip={ip_address}"], check=True)
                messagebox.showinfo("Success", f"IP {ip_address} has been blocked with rule {rule_name}.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to block IP {ip_address}: {str(e)}")
        else:
            messagebox.showwarning("Input Error", "Please enter a valid IP address and rule name.")

    def unblock_ip(self):
        rule_name = self.rule_name_entry.get()
        if rule_name:
            try:
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", 
                                f"name={rule_name}"], check=True)
                messagebox.showinfo("Success", f"Rule {rule_name} has been deleted.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to delete rule {rule_name}: {str(e)}")
        else:
            messagebox.showwarning("Input Error", "Please enter a valid rule name.")

    def block_url(self):
        url = self.url_entry.get()
        rule_name = self.url_rule_name_entry.get()
        
        if url and rule_name:
            try:
                # Extract the domain from the URL
                if url.startswith("http://"):
                    domain = url[7:]
                elif url.startswith("https://"):
                    domain = url[8:]
                else:
                    domain = url
                
                # Remove path components if present
                domain = domain.split("/")[0]
                
                # Method 1: Block using hosts file (more effective for most users)
                self.add_to_hosts_file(domain)
                
                try:
                    # Method 2: Also try to resolve the IP and block it via firewall
                    # Get all IP addresses associated with the domain
                    ip_addresses = []
                    try:
                        # Try to get IPv4 addresses
                        addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET)
                        for addr in addrinfo:
                            ip_addresses.append(addr[4][0])
                    except socket.gaierror:
                        pass
                    
                    try:
                        # Try to get IPv6 addresses
                        addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET6)
                        for addr in addrinfo:
                            ip_addresses.append(addr[4][0])
                    except socket.gaierror:
                        pass
                    
                    # Remove duplicates
                    ip_addresses = list(set(ip_addresses))
                    
                    if ip_addresses:
                        # Block all IP addresses associated with the domain
                        for i, ip_address in enumerate(ip_addresses):
                            # Create unique rule names for each IP
                            suffix = f"_{i}" if i > 0 else ""
                            curr_rule = f"{rule_name}{suffix}"
                            
                            # Create inbound rule
                            subprocess.run([
                                "netsh", "advfirewall", "firewall", "add", "rule", 
                                f"name={curr_rule}", "dir=in", "action=block", 
                                f"remoteip={ip_address}"
                            ], check=True)
                            
                            # Create outbound rule
                            subprocess.run([
                                "netsh", "advfirewall", "firewall", "add", "rule", 
                                f"name={curr_rule}_out", "dir=out", "action=block", 
                                f"remoteip={ip_address}"
                            ], check=True)
                        
                        # Store the domain-to-rule mapping for future reference
                        self.save_url_rule_mapping(domain, rule_name, ip_addresses)
                        
                        ips_str = ", ".join(ip_addresses)
                        messagebox.showinfo(
                            "Success", 
                            f"URL {url} has been blocked via hosts file and firewall rules.\n"
                            f"IPs blocked: {ips_str}"
                        )
                    else:
                        messagebox.showinfo(
                            "Partial Success", 
                            f"URL {url} has been blocked via hosts file only. "
                            "Could not resolve IP addresses for firewall rules."
                        )
                except Exception as e:
                    # If firewall method fails, at least we have the hosts file method
                    messagebox.showinfo(
                        "Partial Success", 
                        f"URL {url} has been blocked via hosts file only.\n"
                        f"Firewall rules could not be added: {str(e)}"
                    )
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to block URL {url}: {str(e)}")
        else:
            messagebox.showwarning("Input Error", "Please enter a valid URL and rule name.")

    def add_to_hosts_file(self, domain):
        """Add a domain to the hosts file to block it"""
        import os
        
        # Path to hosts file
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        
        # Check if we have permission to modify the hosts file
        if not os.access(hosts_path, os.W_OK):
            # Try to run with elevated privileges
            messagebox.showwarning(
                "Permission Required", 
                "Administrator privileges are required to modify the hosts file.\n"
                "Please run the application as Administrator."
            )
            return False
        
        # Read the current hosts file
        with open(hosts_path, 'r') as f:
            hosts_content = f.read()
        
        # Check if the domain is already in the hosts file
        if f"127.0.0.1 {domain}" in hosts_content or f"127.0.0.1  {domain}" in hosts_content:
            # Already blocked
            return True
        
        # Add the domain to the hosts file
        with open(hosts_path, 'a') as f:
            f.write(f"\n127.0.0.1 {domain}")
            f.write(f"\n127.0.0.1 www.{domain}")
        
        return True

    def unblock_url(self):
        rule_name = self.url_rule_name_entry.get()
        url = self.url_entry.get()
        
        if not rule_name and not url:
            messagebox.showwarning("Input Error", "Please enter either a URL or rule name to unblock.")
            return
        
        try:
            # Extract domain if URL is provided
            domain = None
            if url:
                if url.startswith("http://"):
                    domain = url[7:]
                elif url.startswith("https://"):
                    domain = url[8:]
                else:
                    domain = url
                
                # Remove path components if present
                domain = domain.split("/")[0]
                
                # Remove from hosts file
                self.remove_from_hosts_file(domain)
            
            # If rule name is provided, delete firewall rules
            if rule_name:
                # Get the IP addresses associated with this rule
                ip_addresses = self.get_ips_for_rule(rule_name)
                
                # Delete firewall rules for each IP
                for i, _ in enumerate(ip_addresses):
                    suffix = f"_{i}" if i > 0 else ""
                    curr_rule = f"{rule_name}{suffix}"
                    
                    try:
                        # Delete inbound rule
                        subprocess.run([
                            "netsh", "advfirewall", "firewall", "delete", "rule", 
                            f"name={curr_rule}"
                        ], check=True)
                    except:
                        pass
                    
                    try:
                        # Delete outbound rule
                        subprocess.run([
                            "netsh", "advfirewall", "firewall", "delete", "rule", 
                            f"name={curr_rule}_out"
                        ], check=True)
                    except:
                        pass
                
                # Remove the domain-to-rule mapping
                if domain:
                    self.remove_url_rule_mapping(domain)
                else:
                    self.remove_rule_mapping(rule_name)
            
            messagebox.showinfo("Success", "The URL has been unblocked.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unblock URL: {str(e)}")

    def remove_from_hosts_file(self, domain):
        """Remove a domain from the hosts file"""
        import os
        
        # Path to hosts file
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        
        # Check if we have permission to modify the hosts file
        if not os.access(hosts_path, os.W_OK):
            messagebox.showwarning(
                "Permission Required", 
                "Administrator privileges are required to modify the hosts file.\n"
                "Please run the application as Administrator."
            )
            return False
        
        # Read the current hosts file
        with open(hosts_path, 'r') as f:
            hosts_lines = f.readlines()
        
        # Filter out the lines containing the domain
        new_hosts_lines = []
        for line in hosts_lines:
            if not (f"127.0.0.1 {domain}" in line or 
                    f"127.0.0.1  {domain}" in line or
                    f"127.0.0.1 www.{domain}" in line or
                    f"127.0.0.1  www.{domain}" in line):
                new_hosts_lines.append(line)
        
        # Write the modified hosts file
        with open(hosts_path, 'w') as f:
            f.writelines(new_hosts_lines)
        
        return True

    def save_url_rule_mapping(self, domain, rule_name, ip_addresses):
        """Save the domain to rule mapping for future reference"""
        import os
        import json
        
        mapping_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "url_rules.json")
        
        # Load existing mappings
        mappings = {}
        if os.path.exists(mapping_file):
            try:
                with open(mapping_file, 'r') as f:
                    mappings = json.load(f)
            except:
                pass
        
        # Add the new mapping with IP addresses
        mappings[domain] = {
            "rule_name": rule_name,
            "ip_addresses": ip_addresses
        }
        
        # Save the updated mappings
        with open(mapping_file, 'w') as f:
            json.dump(mappings, f, indent=2)

    def get_ips_for_rule(self, rule_name):
        """Get IP addresses associated with a rule name"""
        import os
        import json
        
        mapping_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "url_rules.json")
        
        # Load existing mappings
        if not os.path.exists(mapping_file):
            return []
        
        try:
            with open(mapping_file, 'r') as f:
                mappings = json.load(f)
            
            # Find IP addresses for this rule
            for domain, data in mappings.items():
                if isinstance(data, dict) and data.get("rule_name") == rule_name:
                    return data.get("ip_addresses", [])
                elif data == rule_name:  # Support older format
                    return []
        except:
            pass
        
        return []

    def remove_url_rule_mapping(self, domain):
        """Remove a domain from the mapping file"""
        import os
        import json
        
        mapping_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "url_rules.json")
        
        # Load existing mappings
        if not os.path.exists(mapping_file):
            return
        
        try:
            with open(mapping_file, 'r') as f:
                mappings = json.load(f)
            
            # Remove the domain
            if domain in mappings:
                del mappings[domain]
            
            # Save the updated mappings
            with open(mapping_file, 'w') as f:
                json.dump(mappings, f, indent=2)
        except:
            pass

    def remove_rule_mapping(self, rule_name):
        """Remove mappings for a specific rule name"""
        import os
        import json
        
        mapping_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "url_rules.json")
        
        # Load existing mappings
        if not os.path.exists(mapping_file):
            return
        
        try:
            with open(mapping_file, 'r') as f:
                mappings = json.load(f)
            
            # Find and remove domains with this rule name
            domains_to_remove = []
            for domain, data in mappings.items():
                if isinstance(data, dict) and data.get("rule_name") == rule_name:
                    domains_to_remove.append(domain)
                elif data == rule_name:  # Support older format
                    domains_to_remove.append(domain)
            
            for domain in domains_to_remove:
                del mappings[domain]
            
            # Save the updated mappings
            with open(mapping_file, 'w') as f:
                json.dump(mappings, f, indent=2)
        except:
            pass

    def show_url_rules(self):
        """Show rules that are specifically for blocking URLs"""
        import os
        import json
        
        mapping_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "url_rules.json")
        
        self.rules_window = ctk.CTkToplevel(self)
        self.rules_window.title("URL Blocking Rules")
        self.rules_window.geometry("600x400")
        
        self.rules_text = ctk.CTkTextbox(self.rules_window)
        self.rules_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Display the URL blocking rules
        self.rules_text.configure(state="normal")
        self.rules_text.delete("1.0", "end")
        
        if os.path.exists(mapping_file):
            try:
                with open(mapping_file, 'r') as f:
                    mappings = json.load(f)
                
                if mappings:
                    for domain, rule in mappings.items():
                        self.rules_text.insert("end", f"Domain: {domain} → Rule: {rule}\n")
                else:
                    self.rules_text.insert("end", "No URL blocking rules found.")
            except:
                self.rules_text.insert("end", "Error reading URL rules file.")
        else:
            self.rules_text.insert("end", "No URL blocking rules found.")
        
        self.rules_text.configure(state="disabled")

    def show_firewall_rules(self):
        self.rules_window = ctk.CTkToplevel(self)
        self.rules_window.title("Firewall Rules")
        self.rules_window.geometry("600x400")

        filter_label = ctk.CTkLabel(self.rules_window, text="Filter (rule name or IP):")
        filter_label.pack(pady=5)

        self.filter_entry = ctk.CTkEntry(self.rules_window)
        self.filter_entry.pack(pady=5)

        refresh_button = ctk.CTkButton(self.rules_window, text="Refresh", command=self.refresh_firewall_rules)
        refresh_button.pack(pady=5)

        self.rules_text = ctk.CTkTextbox(self.rules_window)
        self.rules_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.refresh_firewall_rules()

    def refresh_firewall_rules(self):
        filter_value = self.filter_entry.get()
        filter_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
        if filter_value:
            filter_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={filter_value}"]

        try:
            result = subprocess.run(filter_cmd, capture_output=True, text=True, check=True)
            rules = result.stdout

            self.rules_text.configure(state="normal")
            self.rules_text.delete("1.0", "end")
            self.rules_text.insert("1.0", rules)
            self.rules_text.configure(state="disabled")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to retrieve firewall rules: {str(e)}")

if __name__ == "__main__":
    app = FirewallApp()
    app.mainloop()




