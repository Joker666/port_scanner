import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(ip, port):
    """Scans a single port on a given IP."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)  # Timeout for each connection attempt
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"IP: {ip} | Port {port} is open")
            return port

    return None


def scan_ip_range(ip_range, port_range):
    """Scans a range of IPs and ports and returns array of open ports."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for ip in ip_range:
            for port in port_range:
                future = executor.submit(scan_port, ip, port)
                futures.append(future)

        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)

    return open_ports
