#ifndef ARP_INCLUDE_H
#define ARP_INCLUDE_H

#include <stddef.h>
#include <stdint.h>

#define ARP_IPV4_PTYPE 0x0800
#define ARP_ETH_HTYPE 1
#define ARP_HLEN_ETH 6
#define ARP_PLEN_IPV4 4
#define ARP_LEN 28
#define ARP_PAD_LEN 18

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

struct arp_packet {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t hw_len;
	uint8_t proto_len;
	uint16_t op;
	uint8_t sha[6];
	uint32_t spa_be;
	uint8_t tha[6];
	uint32_t tpa_be;
};

size_t arp_parse(const uint8_t *buf, size_t buflen, struct arp_packet *out);

int arp_build(uint8_t *out, uint16_t arp_op_le, uint8_t sha[6], uint8_t tha[6],
	      uint32_t spa_be, uint32_t tpa_be);

size_t arp_write_request(uint8_t *buf, size_t buflen, const uint16_t arp_op_le,
			 const uint8_t sha[6], uint32_t spa_be,
			 const uint8_t tha[6], uint32_t tpa_be);

#endif
