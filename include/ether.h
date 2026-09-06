#ifndef ETH_INCLUDE_H
#define ETH_INCLUDE_H

#define ETH_HDR_LEN 14
#define ETH_MIN_LEN 60
#define ETH_TYPE_ARP 0x0806
#define ETH_PADDING 0x00

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct ethernet_frame {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint32_t tag;
	uint16_t ethertype;
	uint8_t *payload;
};

size_t ether_parse(uint8_t *buf, size_t buflen, struct ethernet_frame *out);

size_t ether_write_frame(uint8_t buf[60], size_t buflen,
			 const uint8_t dst_mac[6], const uint8_t src_mac[6],
			 const uint16_t ethertype_host, const uint8_t *payload,
			 size_t payload_len);

#endif
