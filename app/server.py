import socket
import struct
import argparse
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
        first_16 = self.id
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | \
                (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | \
                (self.z << 4) | self.rcode
        return struct.pack(
            "!HHHHHH",
            first_16,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount
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
        self.resources: List[DNSResource] = []
        self.parse()

    def parse_name(self, offset: int) -> Tuple[bytes, int]:
        result = bytearray()
        current_offset = offset

        while True:
            length = self.data[current_offset]

            if length == 0:
                result.append(0)
                current_offset += 1
                break

            if length & 0xC0 == 0xC0:
                pointer = struct.unpack("!H", self.data[current_offset:current_offset + 2])[0] & 0x3FFF
                pointed_name, _ = self.parse_name(pointer)
                result.extend(pointed_name[:-1])
                current_offset += 2
                if not result or result[-1] != 0:
                    result.append(0)
                break

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

        for _ in range(self.header.ancount):
            name, current_offset = self.parse_name(current_offset)
            type_, class_, ttl, rdlength = struct.unpack(
                "!HHIH", self.data[current_offset:current_offset + 10]
            )
            current_offset += 10
            rdata = self.data[current_offset:current_offset + rdlength]
            current_offset += rdlength
            self.resources.append(DNSResource(name, type_, class_, ttl, rdlength, rdata))


def forward_query(query: DNSQuery, resolver_addr: str, resolver_port: int) -> bytes:
    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward_socket.settimeout(5)

    responses = []
    for question in query.questions:
        single_query = DNSMessage(
            header=DNSHeader(
                id=query.header.id,
                qr=0,
                opcode=query.header.opcode,
                rd=1,
                qdcount=1
            ),
            questions=[question],
            resources=[]
        )

        try:
            forward_socket.sendto(single_query.to_bytes(), (resolver_addr, resolver_port))
            response_data, _ = forward_socket.recvfrom(512)
            responses.append(DNSQuery(response_data))
        except socket.timeout:
            print(f"Timeout while querying resolver for {question}")
            continue
        except Exception as e:
            print(f"Error while forwarding query: {e}")
            continue

    forward_socket.close()

    if not responses:
        return create_error_response(query)

    combined_response = DNSMessage(
        header=DNSHeader(
            id=query.header.id,
            qr=1,
            opcode=query.header.opcode,
            aa=0,
            tc=0,
            rd=query.header.rd,
            ra=1,
            z=0,
            rcode=0,
            qdcount=len(query.questions),
            ancount=sum(len(r.resources) for r in responses),
            nscount=0,
            arcount=0
        ),
        questions=query.questions,
        resources=[res for resp in responses for res in resp.resources]
    )

    return combined_response.to_bytes()


def create_error_response(query: DNSQuery) -> bytes:
    header = DNSHeader(
        id=query.header.id,
        qr=1,
        opcode=query.header.opcode,
        aa=0,
        tc=0,
        rd=query.header.rd,
        ra=1,
        z=0,
        rcode=2,
        qdcount=len(query.questions),
        ancount=0,
        nscount=0,
        arcount=0
    )
    return DNSMessage(header, query.questions, []).to_bytes()


def main():
    parser = argparse.ArgumentParser(description='DNS Forwarding Server')
    parser.add_argument('--resolver', required=True, help='Resolver address in format host:port')
    args = parser.parse_args()

    resolver_host, resolver_port = args.resolver.split(':')
    resolver_port = int(resolver_port)

    print(f"DNS Forwarding Server starting... (forwarding to {resolver_host}:{resolver_port})")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            query = DNSQuery(buf)
            print(f"Received query from {source} with length {len(buf)}")

            response = forward_query(query, resolver_host, resolver_port)
            udp_socket.sendto(response, source)
            print(f"Sent response with length {len(response)}")

        except Exception as e:
            print(f"Error processing request: {e}")
            continue


if __name__ == "__main__":
    main()
