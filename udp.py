class UDPProbes:
    @staticmethod
    def create_dns_query():
        # DNS query for google.com A record
        return bytes([
            0x00, 0x1e,  # Transaction ID
            0x01, 0x00,  # Flags: standard query
            0x00, 0x01,  # Questions: 1
            0x00, 0x00,  # Answer RRs: 0
            0x00, 0x00,  # Authority RRs: 0
            0x00, 0x00,  # Additional RRs: 0
            # Query for google.com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  # google
            0x03, 0x63, 0x6f, 0x6d,  # com
            0x00,  # null terminator
            0x00, 0x01,  # Type: A
            0x00, 0x01   # Class: IN
        ])

    @staticmethod
    def create_ntp_query():
        # NTP version 2 query in client mode
        return bytes([
            0x23,  # LI=0, VN=4, Mode=3 (client)
            0x00,  # Stratum
            0x06,  # Poll
            0xEC,  # Precision
            0x00, 0x00, 0x00, 0x00,  # Root Delay
            0x00, 0x00, 0x00, 0x00,  # Root Dispersion
            0x00, 0x00, 0x00, 0x00,  # Reference ID
            0x00, 0x00, 0x00, 0x00,  # Reference Timestamp
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,  # Origin Timestamp
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,  # Receive Timestamp
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,  # Transmit Timestamp
            0x00, 0x00, 0x00, 0x00
        ])

    @staticmethod
    def create_snmp_query():
        # SNMP v1 GET request
        return bytes([
            0x30, 0x26,             # Sequence, length 38
            0x02, 0x01, 0x00,       # Version: 1
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # Community: "public"
            0xa0, 0x19,             # GET
            0x02, 0x01, 0x00,       # Request ID: 0
            0x02, 0x01, 0x00,       # Error status: 0
            0x02, 0x01, 0x00,       # Error index: 0
            0x30, 0x0e,             # Variable bindings
            0x30, 0x0c,             # Sequence
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # sysDescr.0
            0x05, 0x00              # NULL
        ])

    @staticmethod
    def create_ssdp_query():
        # SSDP M-SEARCH query
        return (
            b'M-SEARCH * HTTP/1.1\r\n'
            b'HOST: 239.255.255.250:1900\r\n'
            b'MAN: "ssdp:discover"\r\n'
            b'MX: 1\r\n'
            b'ST: ssdp:all\r\n\r\n'
        )

    @staticmethod
    def create_netbios_query():
        # NetBIOS name query
        return bytes([
            0x82, 0x28,  # Transaction ID
            0x00, 0x00,  # Flags
            0x00, 0x01,  # Questions
            0x00, 0x00,  # Answer RRs
            0x00, 0x00,  # Authority RRs
            0x00, 0x00,  # Additional RRs
            0x20, 0x43, 0x4b,  # Name
            0x41, 0x41, 0x41,
            0x41, 0x41, 0x41,
            0x41, 0x41, 0x41,
            0x41, 0x41, 0x41,
            0x41, 0x41, 0x41,
            0x41, 0x41, 0x41,
            0x41, 0x41, 0x41,
            0x41, 0x41, 0x41,
            0x41, 0x41, 0x41,
            0x41, 0x41, 0x41,
            0x00,        # End of name
            0x00, 0x21,  # Type: NB
            0x00, 0x01   # Class: IN
        ])

    @staticmethod
    def create_tftp_query():
        # TFTP read request for a test file
        return bytes([
            0x00, 0x01,  # Opcode: Read Request (RRQ)
        ]) + b"test.txt" + b"\0" + b"octet" + b"\0"


def get_common_udp_ports():
    """Returns a dictionary of common UDP ports and their services"""
    return {
        53: ("DNS", UDPProbes.create_dns_query()),
        67: ("DHCP Server", b""),  # DHCP requires specific crafting
        68: ("DHCP Client", b""),  # DHCP requires specific crafting
        69: ("TFTP", UDPProbes.create_tftp_query()),
        123: ("NTP", UDPProbes.create_ntp_query()),
        137: ("NetBIOS Name Service", UDPProbes.create_netbios_query()),
        161: ("SNMP", UDPProbes.create_snmp_query()),
        162: ("SNMP Trap", b""),
        500: ("IKE", b""),  # IPsec key exchange
        514: ("Syslog", b""),
        520: ("RIP", b""),
        1900: ("SSDP", UDPProbes.create_ssdp_query()),
        5353: ("mDNS", UDPProbes.create_dns_query()),  # Multicast DNS
        11211: ("Memcached", b"stats\r\n"),  # Simple memcached stats command
    }

def create_udp_probe(port):
    """Create an appropriate UDP probe packet based on the port"""
    common_ports = get_common_udp_ports()
    return common_ports.get(port, (None, b""))[1]

def analyze_response(port, data):
    """
    Analyze the response data based on the port to confirm if it's valid
    Returns tuple (is_valid, service_info)
    """
    try:
        if port == 53:  # DNS
            return (data[2] & 0x80) != 0, "DNS response received"

        elif port == 123:  # NTP
            if len(data) >= 48:
                version = (data[0] >> 3) & 0x7
                return True, f"NTP version {version}"

        elif port == 161:  # SNMP
            if data[0] == 0x30:  # SEQUENCE tag
                return True, "SNMP response received"

        elif port == 137:  # NetBIOS
            if len(data) > 4:
                return True, "NetBIOS name service response"

        elif port == 1900:  # SSDP
            if b"HTTP/1.1" in data:
                return True, "SSDP response received"

        # For unknown ports, any response might indicate an open port
        return True, "Unknown service response"

    except Exception as e:
        return False, f"Error analyzing response: {str(e)}"