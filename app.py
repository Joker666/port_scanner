from robyn import Request, Robyn

import ports

app = Robyn(__file__)


@app.get("/api/scan/tcp")
def tcp_scan(request: Request):
    ip_range = request.query_params.get("ips").split(",")

    # Convert port range string to array of integers
    port_input = request.query_params.get("ports")
    if "-" in port_input:
        start, end = map(int, port_input.split("-"))
        port_range = list(range(start, end + 1))
    else:
        port_range = [int(port_input)]

    open_ports_by_ip = ports.scan_ip_range(ip_range, port_range)
    return open_ports_by_ip


if __name__ == "__main__":
    app.serve_directory(route="/", directory_path="./ui/dist", index_file="index.html")
    app.start(host="0.0.0.0", port=8080)
