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
        else:
            print(f"IP: {ip} | Port {port} is closed")

    return None


def scan_ip_range(ip_range, port_range):
    """Scans a range of IPs and ports and returns dictionary of IPs with their open ports."""
    open_ports_by_ip = {ip: [] for ip in ip_range}
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for ip in ip_range:
            for port in port_range:
                future = executor.submit(scan_port, ip, port)
                futures.append((ip, future))

        for ip, future in futures:
            result = future.result()
            if result:
                open_ports_by_ip[ip].append(result)

    return open_ports_by_ip
