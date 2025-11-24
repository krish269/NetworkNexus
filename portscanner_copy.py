import os
import socket
import sys
import concurrent.futures
import subprocess
import time


def ping_function(target):
    try:
        output = subprocess.check_output(f"ping {target}", shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except:
        output='Invalid Host'
    return output
   


def grab_banner(ip, port, timeout=3):
    """Attempt to grab service banner from an open port"""
    banner = ""
    try:
        # Create socket and set timeout
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        # Connect to the target port
        s.connect((ip, port))
        
        # Send common probe requests for different services
        probes = [
            b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode(),  # HTTP
            b'EHLO example.com\r\n',  # SMTP
            b'SSH-2.0-OpenSSH_7.6p1\r\n',  # SSH
            b'HELP\r\n',  # FTP/POP3
            b'\x00',  # Some binary protocols
            b''  # Just connect and wait for banner
        ]
        
        # Try each probe and see if we get a response
        for probe in probes:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                
                if probe:
                    sock.send(probe)
                
                # Receive data (up to 1024 bytes)
                data = sock.recv(1024)
                # if data:
                #     banner = data.decode('utf-8', errors='ignore').strip()
                #     break
                
                sock.close()
            except:
                continue
        
        return banner
    except Exception as e:
        return f"Banner grab error: {str(e)}"
    finally:
        try:
            s.close()
        except:
            pass

def enhanced_portscan_function(port):
    """Enhanced port scan function that also grabs banners"""
    protocols = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)  
    result = sock.connect_ex((host, port))
    if result == 0:
        # Get service names
        protocol_list = ['tcp', 'udp']
        for proto in protocol_list:
            try:
                service_name = socket.getservbyport(port, proto)
                print(f'Open Port {port}: Protocol {proto} ------> {service_name}')
                protocols[proto] = service_name
            except OSError:
                protocols[proto] = 'unknown'
        
        # Grab banner
        # banner = grab_banner(host, port)
        # if banner:
        #     protocols['banner'] = banner
        #     print(f'Banner: {banner}')

    sock.close()
    return port, protocols


def port_scanner(host,start_port, end_port):
    open_ports = {}
    max_threads = 1000
    ports = range(start_port, end_port + 1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(enhanced_portscan_function, ports)

        for port, protocols_data in results:
            if protocols_data:
                open_ports[port] = protocols_data

            
        for port, protocols in open_ports.items():
            print(f"Port {port}: ")
            for protocol, service_name in protocols.items():
                if protocol == 'banner':
                    print(f"  Banner: {service_name}")
                else:
                    print(f"  {protocol}: {service_name}")

    return open_ports

def portscannez(target,start_port,end_port):
    global  host
    host = socket.gethostbyname(target)

    open_ports = port_scanner(host,start_port, end_port)
    print('\n\n\n')

    return open_ports


def main(target, start_port, end_port):
    global max_threads
    global host
    max_threads = 1000  # Adjusted to 100 threads for better performance
    try:
        host = socket.gethostbyname(target)
        print(f"Resolved host {target} to {host}")
        result = f"Resolved host {target} to {host}\n"
    except socket.gaierror:
        print("Target is not resolvable")
        result="Target is not resolvable"
        return result

    # Ping the target
    ping_function(target)
    # Port scan
    result += f"Starting port scan from {start_port} to {end_port}\n"
    print(f"Starting port scan from {start_port} to {end_port}")
    open_ports = port_scanner(start_port, end_port)
    print("Open ports and corresponding services found:")
    for port, service in open_ports.items():
        print(f"Port {port}: {service}")


    return result


# Run the main function
if __name__ == "__main__":
    ping_function('xavier.ac.in')
