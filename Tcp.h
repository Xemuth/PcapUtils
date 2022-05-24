#ifndef _pcap_example_Tcp_h_
#define _pcap_example_Tcp_h_

enum TCP_FLAG : unsigned char{
	FIN = 0x1,
	SYN = 0x2,
	RST = 0x4,
	PUSH = 0x8,
	ACK = 0x10,
	URG = 0x20
};

struct TcpHeader{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int sequence_number;
	unsigned int acknowledgment_number;
	unsigned char reserved:4;
	unsigned char data_offset:4;
	TCP_FLAG flags;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

static TcpHeader decode_tcp(const unsigned char* header_start){
	TcpHeader tcp;
	memcpy(&tcp, header_start, sizeof(TcpHeader));
	tcp.src_port = ntohs(tcp.src_port);
	tcp.dst_port = ntohs(tcp.dst_port);
	tcp.sequence_number = ntohl(tcp.sequence_number);
	tcp.acknowledgment_number = ntohl(tcp.acknowledgment_number);
	tcp.window = ntohs(tcp.window);
	tcp.checksum = ntohs(tcp.checksum);
	tcp.urgent_pointer = ntohs(tcp.urgent_pointer);
	return tcp;
}

#endif
