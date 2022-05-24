#ifndef _pcap_example_Ethernet_h_
#define _pcap_example_Ethernet_h_
#include <Core/Core.h>
static const int eth_addr_len = 6;
static const int eth_header_len = 14;

enum EtherType : unsigned short{
	DEC = 0x6000,
	DEC_ = 0x0609,
	XNS = 0x0600,
	IPv4 = 0x0800,
	ARP = 0x0806,
	Domain = 0x8019,
	RARP = 0x8035,
	AppleTalk = 0x809B,
	_802_1Q = 0x8100,
	IPv6 = 0x86DD
};

static const char* ether_type_to_string(EtherType& type){
	switch(type){
		case EtherType::DEC:
			return "DEC";
		case EtherType::DEC_:
			return "DEC";
		case EtherType::XNS:
			return "XNS";
		case EtherType::IPv4:
			return "IPV4";
		case EtherType::ARP:
			return "ARP";
		case EtherType::Domain:
			return "DOMAIN";
		case EtherType::RARP:
			return "RARP";
		case EtherType::AppleTalk:
			return "APPLE_TALK";
		case EtherType::_802_1Q:
			return "802_1Q";
		case EtherType::IPv6:
			return "IPV6";
	}
	return nullptr;
}

struct EthHeader{
	unsigned char source_mac[eth_addr_len];
	unsigned char dest_mac[eth_addr_len];
	EtherType ethernet_packet_type;
};

static EthHeader decode_ethernet(const unsigned char* header_start){
	EthHeader eth;
	memcpy(&eth, header_start, sizeof(EthHeader));
	eth.ethernet_packet_type =  static_cast<EtherType>(ntohs(eth.ethernet_packet_type));
	return eth;
}

#endif
