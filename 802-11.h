#include <cstdint>
#include "mac.h"

#pragma pack(push,1)
struct radiotap_header{
	uint8_t version_;
	uint8_t pad_;
	uint16_t len_;
	uint32_t present_;
};
#pragma pack(pop)

#pragma pack(push,1)
struct deauth_frame{
	uint8_t version_:2;
	uint8_t type_:2;
	uint8_t subtype_:4;
	uint8_t flag_;
	uint16_t duration_;
	Mac receiver_;
	Mac transmitter_;
	Mac bssid_;
	uint16_t seq_;

	uint16_t reason_;
};
#pragma pack(pop)

#pragma pack(push,1)
struct attack_packet{
	radiotap_header rh_;
	deauth_frame df_;

	void init() {
		this->rh_.version_ = 0;
		this->rh_.pad_ = 0;
		this->rh_.len_ = 8;
		this->rh_.present_ = 0;
		this->df_.version_ = 0;
		this->df_.type_ = 0;
		this->df_.subtype_ = 12; // deauth
		this->df_.flag_ = 0;
		this->df_.duration_ = 314; // aireplay 값하고 동일하게..
		this->df_.seq_ = 0;
		this->df_.reason_ = 7;
	}
	void set(Mac recv, Mac trans, Mac bssid) {
		this->df_.receiver_ = recv;
		this->df_.transmitter_ = trans;
		this->df_.bssid_ = bssid;
	}
};
#pragma pack(pop)
