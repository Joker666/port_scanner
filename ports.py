import socket
from concurrent.futures import ThreadPoolExecutor

from robyn import logger
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send, sr1

from udp import analyze_response, create_udp_probe, get_common_udp_ports


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
        probe_data = create_udp_probe(port)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                s.sendto(probe_data, (ip, port))
                data, _ = s.recvfrom(1024)

                is_valid, service_info = analyze_response(port, data)
                if is_valid:
                    return port, "open"

                service_name = get_common_udp_ports().get(port, (f"port {port}", None))[
                    0
                ]
                print(f"{service_name}: Unexpected response")
                return port, "open|filtered"
        except socket.timeout:
            return port, "filtered"  # UDP ports often show as filtered
        except ConnectionRefusedError:
            return port, "closed"
        except Exception as e:
            return port, f"error: {e}"


def get_service_name(port, proto):
    try:
        name = socket.getservbyport(int(port), proto)
    except OSError:
        return None
    return name


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
            if (protocol == "udp" or protocol == "syn") and (
                status == "filtered" or status == "closed"
            ):
                continue

            # Get service name for the port
            service_name = get_service_name(
                port, "tcp" if protocol == "syn" else protocol
            )

            logger.info(
                f"Scanned {ip}:{port} => Status: {status} | Service: {service_name}"
            )

            # Store both service name and status
            open_ports_by_ip[ip][str(port)] = {
                "service": service_name,
                "status": status,
            }

    return open_ports_by_ip
