#ifndef VPNPACKET_H_
#define VPNPACKET_H_


#include <string>


#pragma pack(1)                                             // disable alignment of struct members


class VpnPacket {
public:
	uint16_t        magic = MAGIC;
	uint8_t         msg_type;
	uint16_t        msg_size;

	static constexpr auto MAGIC = 0x484B;
	static constexpr auto MSG_TYPE_HELLO = 10;

	VpnPacket(uint8_t msg_type, uint16_t msg_size);
	VpnPacket(uint8_t msg_type);                            // case message size is unknown (yet) during constructor

	int header_len() const;
	int total_len() const;
	void print_raw() const;
};


class VpnPacketHello : public VpnPacket {
public:
	char            message[16];

	VpnPacketHello(const std::string& message);
};


#endif /* VPNPACKET_H_ */
