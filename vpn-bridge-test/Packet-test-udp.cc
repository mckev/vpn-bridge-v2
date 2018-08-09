#include "pch.h"
#include "Packet.h"


static uint8_t packet[40] = {
	0x45, 0x00, 0x00, 0x28, 0x95, 0x88, 0x40, 0x00, 0x35, 0x11, 0x74, 0x98, 0xdf, 0xe5, 0xce, 0x87,
	0xc6, 0x9a, 0xc6, 0x9c, 0x71, 0x3e, 0x0b, 0xb8, 0x00, 0x14, 0x26, 0xdf, 0x48, 0x65, 0x6c, 0x6c,
	0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64
};


TEST(PacketTestUdp, ParseUdpPacketCorrectly) {
	Ip* ip = (Ip*)packet;
	Udp* udp = (Udp*)ip->data();
	EXPECT_EQ(28990, ntohs(udp->source));
	EXPECT_EQ(3000, ntohs(udp->dest));
	EXPECT_EQ(20, udp->total_len());
	int udp_len_from_ip = ip->total_len() - ip->header_len();
	EXPECT_EQ(20, udp_len_from_ip);
}


TEST(PacketTestUdp, VerifyPayload) {
	Ip* ip = (Ip*)packet;
	Udp* udp = (Udp*)ip->data();
	int payload_len = udp->total_len() - udp->header_len();
	std::string payload_str = std::string((const char*)udp->data(), payload_len);
	EXPECT_EQ(std::string("Hello, world"), payload_str);
}


TEST(PacketTestUdp, CalculateUdpChecksumCorrectly) {
	Ip* ip = (Ip*)packet;
	Udp* udp = (Udp*)ip->data();
	uint16_t original_checksum = udp->check;
	udp->check = 0;
	udp->check = udp->checksum(udp->total_len(), ip->saddr, ip->daddr);
	EXPECT_EQ(original_checksum, udp->check);
}
