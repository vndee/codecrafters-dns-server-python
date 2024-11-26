import socket
import struct
from dataclasses import dataclass
from typing import List, Tuple


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
    questions: List[DNSQuestion]
    resources: List[DNSResource]

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + \
            b''.join(q.to_bytes() for q in self.questions) + \
            b''.join(r.to_bytes() for r in self.resources)


class DNSQuery:
    def __init__(self, data: bytes):
        self.data = data
        self.header = DNSHeader()
        self.questions: List[DNSQuestion] = []
        self.parse()

    def parse_name(self, offset: int) -> Tuple[bytes, int]:
        """Parse a compressed or uncompressed name starting at the given offset."""
        result = bytearray()
        current_offset = offset

        while True:
            length = self.data[current_offset]

            if length == 0:
                # End of name
                result.append(0)
                current_offset += 1
                break

            if length & 0xC0 == 0xC0:
                # This is a pointer
                pointer = struct.unpack("!H", self.data[current_offset:current_offset + 2])[0] & 0x3FFF
                pointed_name, _ = self.parse_name(pointer)
                result.extend(pointed_name[:-1])  # Don't include the terminating 0
                current_offset += 2
                if not result or result[-1] != 0:
                    result.append(0)
                break

            # Regular label
            result.append(length)
            current_offset += 1
            result.extend(self.data[current_offset:current_offset + length])
            current_offset += length

        return bytes(result), current_offset

    def parse(self):
        # Parse header
        self.header.id, flags, self.header.qdcount, self.header.ancount, \
            self.header.nscount, self.header.arcount = struct.unpack("!HHHHHH", self.data[:12])

        self.header.qr = (flags & 0x8000) >> 15
        self.header.opcode = (flags & 0x7800) >> 11
        self.header.aa = (flags & 0x0400) >> 10
        self.header.tc = (flags & 0x0200) >> 9
        self.header.rd = (flags & 0x0100) >> 8
        self.header.ra = (flags & 0x0080) >> 7
        self.header.z = (flags & 0x0070) >> 4
        self.header.rcode = flags & 0x000F

        current_offset = 12
        for _ in range(self.header.qdcount):
            qname, current_offset = self.parse_name(current_offset)
            qtype, qclass = struct.unpack("!HH", self.data[current_offset:current_offset + 4])
            current_offset += 4
            self.questions.append(DNSQuestion(qname, qtype, qclass))


def create_dns_response(query: DNSQuery) -> bytes:
    header = DNSHeader(
        id=query.header.id,
        qr=1,
        opcode=query.header.opcode,
        aa=0,
        tc=0,
        rd=query.header.rd,
        ra=0,
        z=0,
        rcode=0 if query.header.opcode == 0 else 4,
        qdcount=len(query.questions),
        ancount=len(query.questions),
        nscount=0,
        arcount=0
    )

    resources = []
    for question in query.questions:
        resources.append(DNSResource(
            name=question.qname,
            type=question.qtype,
            class_=question.qclass,
            ttl=60,
            rdlength=4,
            rdata=b"\x08\x08\x08\x08"
        ))

    return DNSMessage(header, query.questions, resources).to_bytes()


def main():
    print("DNS Server starting...")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            query = DNSQuery(buf)
            print(f"Received data from {source} with length {len(buf)}: {query}")

            response = create_dns_response(query)
            udp_socket.sendto(response, source)
            print(f"Sent response with length {len(response)}")

        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()