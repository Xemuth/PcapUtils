#include "PcapListener.h"

char get_printable_char(char to_print){
	if(to_print >= 32 && to_print < 127)
		return to_print;
	else
		return'.';
}

Upp::String dump_buffer(const char* buffer, int size, int row_dump_size){
	static const char* hexa = "0123456789ABCDEF";
	Upp::String hexa_dump;
	int row_start_offset = 0;
	int i = 0;
	for(i = 0; i < size; i++){
		if(i != 0 && i % row_dump_size == 0){
			hexa_dump << " | ";
			for(int e = row_start_offset; e < (row_start_offset + row_dump_size); e++){
				hexa_dump << get_printable_char(buffer[e]);
			}
			hexa_dump << "\n";
			row_start_offset = i;
		}
		hexa_dump << hexa[(buffer[i] & 0xF0) >> 4];
		hexa_dump << hexa[(buffer[i] & 0x0F)];
		hexa_dump << " ";
	}
	int remain_to_print = row_dump_size - (i % row_dump_size);
	for( int q = 0; q < (remain_to_print * 3); q++){
		hexa_dump << " ";
	}
	hexa_dump << " | ";
	for(int q = row_start_offset; q < (row_start_offset + (row_dump_size - remain_to_print)); q++){
		hexa_dump << get_printable_char(buffer[q]);
	}
	LOG(hexa_dump);
	return hexa_dump;
}

/*
void dump_buffer(const char* buffer, int size, int row_dump_size){
	static const char* hexa = "0123456789ABCDEF";
	ASSERT_(row_dump_size <= 32, "Invalide size for dump");
	char buffer_row[132];
	buffer_row[ row_dump_size * 3] = '|';
	buffer_row[ row_dump_size * 3 + 1] = ' ';
	int loop_count = (size / row_dump_size) + (((size % row_dump_size) > 0)? 1 : 0);
	const char* position = buffer;
	for(int i = 0; i < loop_count; i++){
		for(int e = 0; e < row_dump_size; e++){
			int pos_letter = 3 * row_dump_size + 3 + e + 1;
			int pos_hexa = e * 3;
			buffer_row[pos_hexa] = hexa[position[0] & 0xF0 >> 4];
			buffer_row[pos_hexa + 1] = hexa[position[0] & 0x0F];
			buffer_row[pos_hexa + 2] = ' ';
			if( position[0] >= 32 and position[0] < 127){
				buffer_row[pos_letter] = position[0];
			}else{
				buffer_row[pos_letter] = '.';
			}
			position++;
		}
		LOG(buffer_row);
	}
}
*/

Upp::String buffer_to_string(const unsigned char* buffer, int size){
	static const char* hexa = "0123456789ABCDEF";
	Upp::String str;
	for(int i = 0; i < size; i++){
		str << hexa[buffer[i] & 0xF0 >> 4] << hexa[buffer[i] & 0x0F] << (i < size ? " ": "");
	}
	return str;
}

namespace Upp{
	
	PcapListener::PcapListener(const char* interface_to_use){
		byte result = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuff);
		ASSERT_(result == 0, "Failled to init pcap: " + Upp::String(interface_to_use));
		pcap_if_t* itf;
		result = pcap_findalldevs(&itf, errbuff);
		ASSERT_(itf && result != -1, "Failled to findAlldevs: " + Upp::String(interface_to_use));
		pcap_if_t* device = find_device(itf, interface_to_use);
		ASSERT_(device, "No device found named " + Upp::String(interface_to_use));
		LOG("Opening listener on " + Upp::String(device->name));
		handle = pcap_create(device->name, errbuff);
		ASSERT_(handle, "Failled to open device, may you have not root priviledge: " + Upp::String(interface_to_use));
		pcap_freealldevs(itf);
		pcap_set_timeout(handle,  300);
		pcap_set_promisc(handle, 1);
		pcap_set_immediate_mode(handle, 1);
		result = pcap_activate(handle);
		ASSERT_(result == 0, "pcap_activate didnt occure correctly, error code: " + AsString(result));
	}
	
	PcapListener::~PcapListener(){
		pcap_close(handle);
	}
	
	PcapListener& PcapListener::RegisterAction(Function<bool (CurrentPacket&)>& filter, Function<void (CurrentPacket&)>& callback){
		if(callbacks_on_filters.Find(&filter) != -1){
			callbacks_on_filters.Get(&filter).Add(&callback);
		}else{
			callbacks_on_filters.Add(&filter).Add(&callback);
		}
		return *this;
	}
	
	PcapListener& PcapListener::RemoveFilter(Function<bool (CurrentPacket&)>& filter){
		if(callbacks_on_filters.Find(&filter) != -1){
			callbacks_on_filters.RemoveKey(&filter);
		}
		return *this;
	}
	
	PcapListener& PcapListener::RemoveAction(Function<bool (CurrentPacket&)>& filter, Function<void (CurrentPacket&)>& callback){
		if(callbacks_on_filters.Find(&filter) != -1){
			int size = callbacks_on_filters.GetCount();
			for(int e = 0; e < size; e++){
				if(callbacks_on_filters.Get(&filter)[e] == &callback){
					callbacks_on_filters.Get(&filter).Remove(e, 1);
					e--;
					size--;
				}
			}
		}
		return *this;
	}
	
	PcapListener& PcapListener::Trace(bool trace){
		trace_packets = trace;
		return *this;
	}
	
	void PcapListener::StartListen(int maximun_request_to_sniff, unsigned char* custom_data){
		custom_data = custom_data;
		pcap_loop(handle, maximun_request_to_sniff, pcap_callback, (u_char*)(this));
	}
	
	void PcapListener::StopListen(){
		pcap_breakloop(handle);
	}
	
	void PcapListener::pcap_callback(unsigned char* pcaplistener, const struct pcap_pkthdr *h, const u_char *bytes){
		PcapListener& listener(*(PcapListener*)pcaplistener);
		listener.pcap_routine(h, bytes);
	}
	
	void PcapListener::pcap_routine(const struct pcap_pkthdr *h, const u_char *bytes){
		CurrentPacket packet = DecodePacket(h, bytes);
		for(Function<bool (CurrentPacket&)>* filter: callbacks_on_filters.GetKeys()){
			if((*filter)(packet)){
				for(Function<void (CurrentPacket&)>* callback : callbacks_on_filters.Get(filter)){
					(*callback)(packet);
				}
			}
		}
	}
	
	PcapListener::CurrentPacket PcapListener::DecodePacket(const struct pcap_pkthdr *h, const u_char *bytes){
		CurrentPacket packet;
		packet.current_listener = this;
		packet.h = h;
		packet.bytes = bytes;
		packet.data_without_header = bytes;
		packet.ethernet = decode_ethernet(bytes);
		if(trace_packets) DumpEthernet(packet.ethernet);
		switch(packet.ethernet.ethernet_packet_type){
			case EtherType::IPv4:
				packet.ipv4 = decode_ipv4(bytes + sizeof(packet.ethernet));
				if(trace_packets) DumpIPv4(packet.ipv4);
				if(packet.ipv4 .protocol == 0X06){ // Tcp
					packet.tcp = decode_tcp(bytes + sizeof(packet.ethernet) + sizeof(packet.ipv4));
					packet.data_without_header = bytes + sizeof(packet.ethernet) + sizeof(packet.ipv4) + (packet.tcp.data_offset * sizeof(int32 )); // False, should look for the size of tcp
					if(trace_packets) DumpTcp(packet.tcp);
				}
			break;
			case EtherType::IPv6:
				packet.ipv6 = decode_ipv6(bytes + sizeof(packet.ethernet));
				if(trace_packets) DumpIPv6(packet.ipv6);
				if(packet.ipv6.next_header == 0x06){ //TCP
					packet.tcp = decode_tcp(bytes + sizeof(packet.ethernet) + sizeof(packet.ipv6));
					packet.data_without_header = bytes + sizeof(packet.ethernet) + sizeof(packet.ipv6) + sizeof(packet.tcp) + packet.tcp.data_offset;
					if(trace_packets) DumpTcp(packet.tcp);
				}
			break;
		}
		return packet;
	}
	
	void PcapListener::DumpPacket(CurrentPacket& packet){
		Cout() << "---------------------------------------" << EOL;
		Cout() << "Packet size: " << AsString(packet.h->len) << EOL;
		DumpEthernet(packet.ethernet);
		switch(packet.ethernet.ethernet_packet_type){
			case EtherType::IPv4:
				DumpIPv4(packet.ipv4);
				if(packet.ipv4 .protocol == 0X06) // Tcp
					DumpTcp(packet.tcp);
			break;
			case EtherType::IPv6:
				DumpIPv6(packet.ipv6);
				if(packet.ipv6.next_header == 0x06) // Tcp
					DumpTcp(packet.tcp);
			break;
		}
	}
	
	void PcapListener::DumpEthernet(EthHeader& packet_header){
		Cout() << "-------- Ethernet header --------------" << EOL;
		unsigned char* mac = packet_header.source_mac;
		Cout() << "\t" << "Mac source: " << Format("%02X.%02X.%02X.%02X.%02X.%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]) << EOL;
		mac = packet_header.dest_mac;
		Cout() << "\t" << "Mac destination: " << Format("%02X.%02X.%02X.%02X.%02X.%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]) << EOL;
		Cout() << "\t" << "Protocol: " << ether_type_to_string(packet_header.ethernet_packet_type) << EOL;
	}
	
	void PcapListener::DumpIPv4(Ipv4Header& packet_header){
		Cout() << "-------- IPv4 header --------------" << EOL;
		Cout() << "\t" << "Version: " << Format("%x", packet_header.version) << EOL;
		Cout() << "\t" << "Header length: " << Format("%d", packet_header.header_length) << EOL;
		Cout() << "\t" << "Type of service: " << Format("%x", packet_header.type_of_service) << EOL;
		Cout() << "\t" << "Total length: " << Format("%d", packet_header.total_length) << EOL;
		Cout() << "\t" << "Identification number: " << Format("%d", packet_header.identification_number) << EOL;
		Cout() << "\t" << "Flags: " << Format("%x", packet_header.flags) << EOL;
		Cout() << "\t" << "Fragment offset: " << Format("%d", packet_header.offset) << EOL;
		Cout() << "\t" << "Time to live: " << Format("%d", packet_header.time_to_live) << EOL;
		Cout() << "\t" << "Protocol: " << Format("%x",packet_header.protocol) << EOL;
		Cout() << "\t" << "Header_checksum: " << Format("%04X", packet_header.header_checksum) << EOL;
		char src[16]; Ipv4ToCStr(packet_header.src_addr, src, 16);
		char dst[16]; Ipv4ToCStr(packet_header.dest_addr, dst, 16);
		Cout() << "\t" << "Source address IPv4: " << Format("%s", src) << EOL;
		Cout() << "\t" << "Destination address IPv4: " << Format("%s", dst) << EOL;
	}
	
	void PcapListener::DumpIPv6(Ipv6Header& packet_header){
		//TODO
	}
	
	void PcapListener::DumpTcp(TcpHeader& packet_header){
		Cout() << "--------- TCP header ---------------" << EOL;
		Cout() << "\t" << "Port source: " << Format("%d", packet_header.src_port) << EOL;
		Cout() << "\t" << "Port destination: " << Format("%d", packet_header.dst_port) << EOL;
		Cout() << "\t" << "Sequence number: " << packet_header.sequence_number << EOL;
		Cout() << "\t" << "Acknowledgment number: " << packet_header.acknowledgment_number << EOL;
		Cout() << "\t" << "Reserved: " << Format("%d", packet_header.reserved) << EOL;
		Cout() << "\t" << "Data offset: " << Format("%d", packet_header.data_offset) << EOL;
		Cout() << "\t" << "Flags: " << Format("%x", packet_header.flags) << EOL;
		Cout() << "\t" << "Window: " << Format("%d", packet_header.window) << EOL;
		Cout() << "\t" << "Checksum: " << Format("%04x", packet_header.checksum) << EOL;
		Cout() << "\t" << "Urgent pointer: " << Format("%x", packet_header.urgent_pointer) << EOL;
	}

	pcap_if_t* PcapListener::find_device(pcap_if_t* itf, const char* name){
		pcap_if_t* buffer = itf;
		while(buffer){
			if(strcmp(buffer->name, name) == 0)
				return buffer;
			buffer = buffer->next;
		}
		return nullptr;
	}
	
}