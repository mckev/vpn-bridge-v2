#include "pch.h"
#include "Packet.h"


static uint8_t packet[41] = {
	0x45, 0x00, 0x00, 0x29, 0x92, 0x23, 0x40, 0x00, 0x35, 0x11, 0x5b, 0xe9, 0x6a, 0xc9, 0x5f, 0xb7,
	0xc6, 0x9a, 0xc6, 0x9c, 0x74, 0x8b, 0x0b, 0xb8, 0x00, 0x15, 0xe6, 0x7c, 0x48, 0x65, 0x6c, 0x6c,
	0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21
};

TEST(PacketTestUdp, ParseUdpPacketCorrectly) {
	Ip* ip = (Ip*)packet;
	Udp* udp = (Udp*)ip->data();
	EXPECT_EQ(29835, ntohs(udp->source));
	EXPECT_EQ(3000, ntohs(udp->dest));
	EXPECT_EQ(21, udp->total_len());
	int udp_len_from_ip = ip->total_len() - ip->header_len();
	EXPECT_EQ(udp->total_len(), udp_len_from_ip);
}

TEST(PacketTestUdp, VerifyPayload) {
	Ip* ip = (Ip*)packet;
	Udp* udp = (Udp*)ip->data();
	int payload_len = udp->total_len() - udp->header_len();
	std::string payload_str = std::string((const char*)udp->data(), payload_len);
	EXPECT_EQ(std::string("Hello, world!"), payload_str);
}

TEST(PacketTestUdp, CalculateUdpChecksumCorrectly) {
	Ip* ip = (Ip*)packet;
	Udp* udp = (Udp*)ip->data();
	int len = ip->total_len() - ip->header_len();
	uint16_t original_checksum = udp->check;
	udp->check = 0;
	udp->check = udp->checksum(len, ip->saddr, ip->daddr);
	EXPECT_EQ(original_checksum, udp->check);
}
