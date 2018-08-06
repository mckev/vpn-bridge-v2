#include "pch.h"
#include "Packet.h"


TEST(PacketTest, CanConvertUint32IntoIpAddress) {
	uint32_t ip_addr;
	ip_addr = 0x87cee5df;
	EXPECT_EQ(std::string("223.229.206.135"), Ip::ip_addr_to_str(ip_addr));
	ip_addr = 0x9cc69ac6;
	EXPECT_EQ(std::string("198.154.198.156"), Ip::ip_addr_to_str(ip_addr));
}


TEST(PacketTest, CanParseIpPacketCorrectly) {
	uint8_t buffer[20] = {
		0x45, 0x00, 0x00, 0x28, 0x95, 0x88, 0x40, 0x00, 0x35, 0x11, 0x74, 0x98, 0xdf, 0xe5, 0xce, 0x87,
		0xc6, 0x9a, 0xc6, 0x9c
	};
	Ip* ip = (Ip*)buffer;
	EXPECT_EQ(4, ip->version);
	EXPECT_EQ(20, ip->ihl * 4);				// length of ip header
	EXPECT_EQ(40, ntohs(ip->tot_len));		// total length (length of ip header + payload)
	EXPECT_EQ(38280, ntohs(ip->id));
	EXPECT_EQ(53, ip->ttl);
	EXPECT_EQ(Ip::IPPROTO_UDP, ip->protocol);
	EXPECT_EQ(std::string("223.229.206.135"), Ip::ip_addr_to_str(ip->saddr));
	EXPECT_EQ(std::string("198.154.198.156"), Ip::ip_addr_to_str(ip->daddr));
}


TEST(PacketTest, CanCalculateIpChecksumCorrectly) {
	uint8_t buffer[20] = {
		0x45, 0x00, 0x00, 0x28, 0x95, 0x88, 0x40, 0x00, 0x35, 0x11, 0x74, 0x98, 0xdf, 0xe5, 0xce, 0x87,
		0xc6, 0x9a, 0xc6, 0x9c
	};
	Ip* ip = (Ip*)buffer;
	ip->check = 0;
	EXPECT_EQ(29848, ntohs(ip->checksum()));
}
