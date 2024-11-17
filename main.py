import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(ip, port):
    """Scans a single port on a given IP."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)  # Timeout for each connection attempt
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"IP: {ip} | Port {port} is open")
            # Optional: Infer service based on port number
            common_ports = {22: "SSH", 80: "HTTP", 443: "HTTPS", 21: "FTP", 25: "SMTP"}
            service = common_ports.get(port, "Unknown Service")
            print(f"Service inferred: {service}")


def scan_ip_range(ip_range, port_range):
    """Scans a range of IPs and ports."""
    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in ip_range:
            for port in port_range:
                executor.submit(scan_port, ip, port)


port_range = range(20, 1025)  # Scan ports 20 through 1024

# Start scanning
ip_range = ["164.90.142.90"]
scan_ip_range(ip_range, port_range)
