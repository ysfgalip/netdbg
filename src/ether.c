#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/ether.h"

size_t ether_parse(struct ethhdr *out, uint8_t *buf, size_t buflen)
{
	if (buflen < 60) {
		return 0;
	}

	struct ethhdr temp = {0};
	uint8_t *w = buf;

	memcpy(temp.h_dest, w, sizeof(temp.h_dest));
	w += sizeof(temp.h_dest);

	memcpy(temp.h_source, w, sizeof(temp.h_source));
	w += sizeof(temp.h_source);

	memcpy(&temp.h_proto, w, sizeof(temp.h_proto));
	if (temp.h_proto == htons(ETH_P_8021Q)) {
		return 0;
	}
	w += sizeof(temp.h_proto);

	return w - buf;
}

size_t ether_build(struct ethhdr *out, const uint8_t dst_mac[6],
		   const uint8_t src_mac[6], const uint16_t ethertype_host)
{
	struct ethhdr temp = {0};

	const uint16_t ethertype_be = htons(ethertype_host);

	memcpy(temp.h_dest, dst_mac, 6);
	memcpy(temp.h_source, src_mac, 6);
	temp.h_proto = ethertype_be;

	memcpy(out, &temp, sizeof(temp));

	size_t written_length = ETH_HDR_LEN;
	return written_length;
}

size_t ether_build_frame(uint8_t *out, struct ethhdr *header, uint8_t *payload,
			 size_t payload_len, size_t mtu)
{
	size_t frame_size = ETH_HDR_LEN + payload_len;
	size_t padding_length = 0;
	if (frame_size > mtu) {
		return 0;
	}

	uint8_t *w = out;
	memcpy(w, header->h_dest, 6);
	w += 6;
	memcpy(w, header->h_source, 6);
	w += 6;
	memcpy(w, &header->h_proto, 2);
	w += 2;
	memcpy(w, payload, payload_len);
	w += payload_len;

	if (frame_size < 60) {
		padding_length = ETH_MIN_LEN - frame_size;
		memset(w, '\0', padding_length);
		w += padding_length;
	}

	return w - out;
}
