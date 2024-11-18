import socket
from concurrent.futures import ThreadPoolExecutor

from robyn import logger


def scan_port(tracing_id, ip, port):
    """Scans a single port on a given IP and returns tuple of (port, status)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)  # Timeout for each connection attempt
        result = s.connect_ex((ip, port))
        if result == 0:
            logger.info(f"Tracing ID: {tracing_id} | IP: {ip} | Port {port} is open")
            return port, "open"
        else:
            logger.info(f"Tracing ID: {tracing_id} | IP: {ip} | Port {port} is closed")
            return port, "closed"


def scan_ip_range(tracing_id, ip_range, port_range, concurrency=10):
    """Scans a range of IPs and ports and returns dictionary of IPs with their port:status mappings."""
    open_ports_by_ip = {ip: {} for ip in ip_range}
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for ip in ip_range:
            for port in port_range:
                future = executor.submit(scan_port, tracing_id, ip, port)
                futures.append((ip, future))

        for ip, future in futures:
            port, status = future.result()

            if status == "closed":
                continue
            open_ports_by_ip[ip][str(port)] = status

    return open_ports_by_ip
