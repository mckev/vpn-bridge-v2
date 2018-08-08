#include "pch.h"
#include "Packet.h"


static uint8_t packet[40] = {
	0x45, 0x00, 0x00, 0x28, 0x95, 0x88, 0x40, 0x00, 0x35, 0x11, 0x74, 0x98, 0xdf, 0xe5, 0xce, 0x87,
	0xc6, 0x9a, 0xc6, 0x9c, 0x71, 0x3e, 0x0b, 0xb8, 0x00, 0x14, 0x26, 0xdf, 0x48, 0x65, 0x6c, 0x6c,
	0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64
};


TEST(PacketTestUdp, ParseUdpPacketCorrectly) {
	Ip* ip = (Ip*)packet;
	Udp* udp = (Udp*)((uint8_t*)ip + (ip->ihl * 4));
	EXPECT_EQ(28990, ntohs(udp->source));
	EXPECT_EQ(3000, ntohs(udp->dest));
	EXPECT_EQ(20, ntohs(udp->len));
	int udp_len_from_ip = ntohs(ip->tot_len) - (ip->ihl * 4);
	EXPECT_EQ(20, udp_len_from_ip);
}


TEST(PacketTestUdp, VerifyPayload) {
	Ip* ip = (Ip*)packet;
	Udp* udp = (Udp*)((uint8_t*)ip + (ip->ihl * 4));
	int udp_len = ntohs(udp->len);
	const uint8_t* payload = (uint8_t*)((uint8_t*)udp + sizeof(Udp));
	int payload_len = udp_len - sizeof(Udp);
	std::string payload_str = std::string((const char*)payload, payload_len);
	EXPECT_EQ(std::string("Hello, world"), payload_str);
}


TEST(PacketTestUdp, CalculateUdpChecksumCorrectly) {
	Ip* ip = (Ip*)packet;
	Udp* udp = (Udp*)((uint8_t*)ip + (ip->ihl * 4));
	int udp_len = ntohs(udp->len);
	uint16_t original_checksum = udp->check;
	udp->check = 0;
	EXPECT_EQ(original_checksum, udp->checksum(udp_len, ip->saddr, ip->daddr));
	udp->check = original_checksum;
}
