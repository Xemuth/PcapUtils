#ifndef _pcap_example_Ip_h_
#define _pcap_example_Ip_h_

static const int ipv6_addr_len = 16;

static void Ipv4ToCStr(const unsigned int ip,char* buffer, unsigned short buffer_size){
	int offset = 0;
	if(buffer_size >= 16){ // We count for size of ip as string + null charactere
		for(int e = 3; e > -1; e--){
			short ipv4_byte = ip >> (e * 8) & 0xFF;
			offset += sprintf(&buffer[offset], "%d.", ipv4_byte);
		}
		buffer[offset - 1] = '\0';
	}
}

struct Ipv4Header{
	byte version:4;
	byte header_length:4;
	unsigned char type_of_service;
	unsigned short total_length;
	unsigned short identification_number;
	unsigned short flags:3;
	unsigned short offset:13;
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short header_checksum;
	unsigned int src_addr;
	unsigned int dest_addr;
}__attribute__((packed));

static Ipv4Header decode_ipv4(const unsigned char* header_start){
	Ipv4Header ip;
	memcpy(&ip, header_start, sizeof(Ipv4Header));
	
	// x86 little endian mean we have to inverte both value
	byte old_version = ip.version;
	ip.version = ip.header_length;
	ip.header_length = old_version;
	
	ip.total_length = ntohs(ip.total_length);
	ip.identification_number = ntohs(ip.identification_number);
	ip.header_checksum = ntohs(ip.header_checksum);
	ip.src_addr = ntohl(ip.src_addr);
	ip.dest_addr = ntohl(ip.dest_addr);
	
	byte* short_flag_and_offset = (byte*) &ip;
	short_flag_and_offset += 6;
	*((short*)short_flag_and_offset) = ntohs(*((short*)short_flag_and_offset)); // Converting the bitfield
	
	return ip;
}

struct Ipv6Header{
	byte version:4;
	byte traffic_class:8;
	int flow_label:20;
	short payload_length;
	byte next_header;
	byte hop_limit;
	unsigned char src_addr[ipv6_addr_len];
	unsigned char dest_addr[ipv6_addr_len];
}__attribute__((packed));

static Ipv6Header decode_ipv6(const unsigned char* header_start){
	Ipv6Header ip;
	memcpy(&ip, header_start, sizeof(Ipv6Header));
	ip.flow_label = ntohl(ip.flow_label);
	ip.payload_length = ntohs(ip.payload_length);
	return ip;
}

#endif
