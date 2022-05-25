#ifndef _pcap_callback_pcap_callback_h_
#define _pcap_callback_pcap_callback_h_
#include <Core/Core.h>
#include <pcap/pcap.h>
#include "Ethernet.h"
#include "Ip.h"
#include "Tcp.h"

Upp::String dump_buffer(const char* buffer, int size, int row_dump_size, bool add_ascii_interpretation = true);

namespace Upp{

class PcapListener{
	/*
		Init pcap and listen for incoming packet.
		For each packet filter callback is triggered and allow or not the callback to be
		executed.
	*/
	public:
		struct CurrentPacket{ // For now we only plan to catch IPV4
			public:
				EthHeader ethernet;
				union {
					Ipv4Header ipv4;
					Ipv6Header ipv6;
				};
				union{
					TcpHeader tcp;
				};
				TcpOptions options;
				int data_size;
				u_char const * data_without_header;
				const struct pcap_pkthdr *h;
				const u_char *bytes;
				unsigned char* custom_data;
				PcapListener* current_listener;
		};
	
	public:
		PcapListener() = delete;
		PcapListener(PcapListener&) = delete;
		PcapListener(const char* interface_to_use);
		~PcapListener();
		
		/*
			TODO: Creation de l'ajout / supression d'action et de filtre ici.
		*/
		
		PcapListener& RegisterAction(Function<bool (CurrentPacket&)>& filter, Function<void (CurrentPacket&)>& callback);
		PcapListener& RemoveFilter(Function<bool (CurrentPacket&)>& filter);
		PcapListener& RemoveAction(Function<bool (CurrentPacket&)>& filter, Function<void (CurrentPacket&)>& callback);
		PcapListener& Trace(bool trace=true);
		
		void StartListen(int maximun_request_to_sniff = -1, unsigned char* custom_data = nullptr);
		void StopListen(); // Only call pcap_breakloop()
		void DumpPacket(CurrentPacket& packet);
		
	private:
		bool trace_packets = false;
		void pcap_routine(const struct pcap_pkthdr *h, const u_char *bytes);
		CurrentPacket DecodePacket(const struct pcap_pkthdr *h, const u_char *bytes);
		pcap_t* handle = nullptr;
		char errbuff[PCAP_ERRBUF_SIZE + 1];
		pcap_if_t* find_device(pcap_if_t* itf, const char* name);
		static void pcap_callback(unsigned char* pcaplistener, const struct pcap_pkthdr *h, const u_char *bytes);
		
		void DumpEthernet(EthHeader& packet_header);
		void DumpIPv4(Ipv4Header& packet_header);
		void DumpIPv6(Ipv6Header& packet_header);
		void DumpTcp(CurrentPacket& packet_header);
		
		/* TODO: Gestion des filtres et des actions ici */
		unsigned char* custom_data = nullptr;
		ArrayMap<Function<bool (CurrentPacket&)>*, Array<Function<void (CurrentPacket&)>*>> callbacks_on_filters; // For each filter we can have multiple callback
};

}

#endif
