#include "pch.h"
#include "Packet.h"


static uint8_t packet[20] = {
	0x45, 0x00, 0x00, 0x29, 0x92, 0x23, 0x40, 0x00, 0x35, 0x11, 0x5b, 0xe9, 0x6a, 0xc9, 0x5f, 0xb7,
	0xc6, 0x9a, 0xc6, 0x9c
};


TEST(PacketTestIp, ConvertIpAddressFromUint32IntoStr) {
	uint32_t ip_addr1 = 0xb75fc96a;
	EXPECT_EQ(std::string("106.201.95.183"), Ip::ip_addr_to_str(ip_addr1));
	uint32_t ip_addr2 = 0x9cc69ac6;
	EXPECT_EQ(std::string("198.154.198.156"), Ip::ip_addr_to_str(ip_addr2));
}


TEST(PacketTestIp, ParseIpPacketCorrectly) {
	Ip* ip = (Ip*)packet;
	EXPECT_EQ(4, ip->version);
	EXPECT_EQ(20, ip->header_len());
	EXPECT_EQ(41, ip->total_len());
	EXPECT_EQ(37411, ntohs(ip->id));
	EXPECT_EQ(53, ip->ttl);
	EXPECT_EQ(Ip::IPPROTO_UDP, ip->protocol);
	EXPECT_EQ(std::string("106.201.95.183"), Ip::ip_addr_to_str(ip->saddr));
	EXPECT_EQ(std::string("198.154.198.156"), Ip::ip_addr_to_str(ip->daddr));
}


TEST(PacketTestIp, CalculateIpChecksumCorrectly) {
	Ip* ip = (Ip*)packet;
	uint16_t original_checksum = ip->check;
	ip->check = 0;
	ip->check = ip->checksum();
	EXPECT_EQ(original_checksum, ip->check);
}
