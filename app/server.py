import socket
import struct
from dataclasses import dataclass
from typing import List


@dataclass
class DNSHeader:
    id: int = 0  # 16 bits
    qr: int = 0  # 1 bit
    opcode: int = 0  # 4 bits
    aa: int = 0  # 1 bit
    tc: int = 0  # 1 bit
    rd: int = 0  # 1 bit
    ra: int = 0  # 1 bit
    z: int = 0  # 3 bits
    rcode: int = 0  # 4 bits
    qdcount: int = 0  # 16 bits
    ancount: int = 0  # 16 bits
    nscount: int = 0  # 16 bits
    arcount: int = 0  # 16 bits

    def to_bytes(self) -> bytes:
        # Pack the first 16 bits: ID
        first_16 = self.id

        # Pack the next 16 bits: QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1) | RA(1) | Z(3) | RCODE(4)
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | \
                (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | \
                (self.z << 4) | self.rcode

        # Pack everything into bytes using network byte order (big-endian)
        return struct.pack(
            "!HHHHHH",
            first_16,  # ID
            flags,  # Flags
            self.qdcount,  # QDCOUNT
            self.ancount,  # ANCOUNT
            self.nscount,  # NSCOUNT
            self.arcount  # ARCOUNT
        )


@dataclass
class DNSQuestion:
    qname: bytes
    qtype: int
    qclass: int

    def to_bytes(self) -> bytes:
        return self.qname + struct.pack("!HH", self.qtype, self.qclass)


@dataclass
class DNSResource:
    name: bytes
    type: int
    class_: int
    ttl: int
    rdlength: int
    rdata: bytes

    def to_bytes(self) -> bytes:
        return self.name + struct.pack("!HHIH", self.type, self.class_, self.ttl, self.rdlength) + self.rdata


@dataclass
class DNSMessage:
    header: DNSHeader
    question: List[DNSQuestion]
    resource: List[DNSResource] = None

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + b''.join([q.to_bytes() for q in self.question]) + b''.join([r.to_bytes() for r in self.resource])


@dataclass
class DNSQuery:
    def __init__(self, data: bytes):
        self.data = data
        self.header = DNSHeader()
        self.question = DNSQuestion(b'', 0, 0)

        self.parse()

    def parse(self):
        self.header.id, flags, self.header.qdcount, self.header.ancount, self.header.nscount, self.header.arcount = struct.unpack("!HHHHHH", self.data[:12])
        self.header.qr = (flags & 0x8000) >> 15
        self.header.opcode = (flags & 0x7800) >> 11
        self.header.aa = (flags & 0x0400) >> 10
        self.header.tc = (flags & 0x0200) >> 9
        self.header.rd = (flags & 0x0100) >> 8
        self.header.ra = (flags & 0x0080) >> 7
        self.header.z = (flags & 0x0070) >> 4
        self.header.rcode = flags & 0x000F

        qname = self.data[12:]
        self.question.qname = qname[:qname.index(b'\x00') + 1]
        self.question.qtype, self.question.qclass = struct.unpack("!HH", qname[len(self.question.qname):len(self.question.qname) + 4])


def create_dns_response(packet_id: int) -> bytes:
    header = DNSHeader(
        id=packet_id,
        qr=1,
        opcode=0,
        aa=0,
        tc=0,
        rd=0,
        ra=0,
        z=0,
        rcode=0,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0
    )

    question = DNSQuestion(
        qname=b'\x0ccodecrafters\x02io\x00',
        qtype=1,
        qclass=1
    )

    resource = DNSResource(
        name=b'\x0ccodecrafters\x02io\x00',
        type=1,
        class_=1,
        ttl=60,
        rdlength=4,
        rdata=b"\x08\x08\x08\x08"
    )

    return DNSMessage(header, [question], [resource]).to_bytes()


def main():
    print("DNS Server starting...")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print(f"Received data from {source} with length {len(buf)}: {buf}")

            query = DNSQuery(buf)
            response = create_dns_response(query.header.id)
            udp_socket.sendto(response, source)
            print(f"Sent response with length {len(response)}")

        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
