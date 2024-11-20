import socket
from concurrent.futures import ThreadPoolExecutor

from scapy.all import *


def scan_port(tracing_id, ip, port, protocol="tcp"):
    """Scans a single port on a given IP and returns tuple of (port, status)."""
    if protocol == "tcp":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, port))
                return port, "open"
        except socket.timeout:
            return port, "filtered"
        except ConnectionRefusedError:
            return port, "closed"
        except Exception as e:
            return port, f"error: {e}"
    if protocol == "syn":
        syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)
        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                # Port is open, since we received SYN-ACK
                # Send RST to close the connection gracefully
                rst_packet = IP(dst=ip) / TCP(dport=port, flags="R")
                send(rst_packet, verbose=0)

                return port, "open"
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                return port, "closed"
        else:
            return port, "filtered"
    else:  # UDP scan
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                s.sendto(b"", (ip, port))
                data, _ = s.recvfrom(1024)
                return port, "open"
        except socket.timeout:
            return port, "filtered"  # UDP ports often show as filtered
        except ConnectionRefusedError:
            return port, "closed"
        except Exception as e:
            return port, f"error: {e}"


def scan_ip_range(tracing_id, ip_range, port_range, protocol="tcp", concurrency=10):
    """Scans a range of IPs and ports and returns dictionary of IPs with their port:status mappings."""
    open_ports_by_ip = {ip: {} for ip in ip_range}
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for ip in ip_range:
            for port in port_range:
                future = executor.submit(scan_port, tracing_id, ip, port, protocol)
                futures.append((ip, future))

        for ip, future in futures:
            port, status = future.result()
            if protocol == "tcp" and status == "filtered":
                continue
            if protocol == "udp" and (status == "filtered" or status == "closed"):
                continue
            open_ports_by_ip[ip][str(port)] = status

    return open_ports_by_ip
