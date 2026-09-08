#ifndef ETH_INCLUDE_H
#define ETH_INCLUDE_H

#include <stdint.h>
#include <string.h>

#define ETH_HDR_LEN 14
#define ETH_MIN_LEN 56
#define ETH_MAX_LEN 1514
#define ETH_TYPE_ARP 0x0806
#define ETH_PADDING 0x00

struct ethernet_frame {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t ethertype;
	uint8_t *payload;
};

size_t ether_parse(struct ethhdr *out, uint8_t *buf, size_t buflen);

size_t ether_build(struct ethhdr *out, const uint8_t dst_mac[6],
		   const uint8_t src_mac[6], const uint16_t ethertype_host);

size_t ether_write_frame(uint8_t buf[60], size_t buflen,
			 const uint8_t dst_mac[6], const uint8_t src_mac[6],
			 const uint16_t ethertype_host, const uint8_t *payload,
			 size_t payload_len);

size_t ether_build_frame(uint8_t *out, struct ethhdr *header, uint8_t *payload,
			 size_t payload_len, size_t mtu);

#endif
