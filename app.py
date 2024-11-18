import hashlib
import time

from robyn import Request, Robyn

import ports

app = Robyn(__file__)


@app.get("/api/scan/tcp")
def tcp_scan(request: Request):
    # Create tracing ID from request attributes
    tracing_id = create_request_hash(request)
    concurrency = int(request.query_params.get("concurrency"))

    open_ports_by_ip = ports.scan_ip_range(
        tracing_id, get_ip_range(request), get_port_range(request), concurrency
    )
    return open_ports_by_ip


def get_ip_range(request: Request) -> list:
    """
    Extracts IP range from the request query parameters.
    """
    ip_range = request.query_params.get("ips")
    if not ip_range:
        return []
    return [ip.strip() for ip in ip_range.split(",")]


def get_port_range(request: Request) -> list:
    """
    Extracts port range from the request query parameters.
    """
    port_input = request.query_params.get("ports")
    if "-" in port_input:
        start, end = map(int, port_input.split("-"))
        port_range = list(range(start, end + 1))
    else:
        port_range = [int(port_input)]
    return port_range


def create_request_hash(request: Request) -> str:
    """
    Creates a unique hash from request attributes.
    """
    # Collect various attributes to make the hash unique
    timestamp = str(time.time())

    # Create a string combining multiple attributes
    hash_input = "|".join(
        [
            timestamp,
            request.ip_addr or "",
            request.method,
        ]
    )

    # Create SHA-256 hash
    hash_object = hashlib.sha256(hash_input.encode())
    # Take first 12 characters of the hexadecimal representation
    return hash_object.hexdigest()[:12]


if __name__ == "__main__":
    app.serve_directory(route="/", directory_path="./ui/dist", index_file="index.html")
    app.start(host="0.0.0.0", port=8080)
