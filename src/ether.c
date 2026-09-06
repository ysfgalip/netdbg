#include "../include/ether.h"
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

size_t ether_parse(uint8_t *buf, size_t buflen, struct ethernet_frame *out)
{
	if (buflen < 60) {
		return 0;
	}

	struct ethernet_frame temp = {0};
	uint8_t *w = buf;

	memcpy(temp.dst_mac, w, sizeof(temp.dst_mac));
	w += sizeof(temp.dst_mac);

	memcpy(temp.src_mac, w, sizeof(temp.src_mac));
	w += sizeof(temp.src_mac);

	memcpy(&temp.ethertype, w, sizeof(temp.ethertype));
	if (temp.ethertype == htons(ETH_P_8021Q)) {
		return 0;
	}
	w += sizeof(temp.ethertype);

	int payload_length = buflen - ETH_HDR_LEN;
	temp.payload = malloc(payload_length);
	if (!temp.payload) {
		return 0;
	}
	memcpy(temp.payload, w, payload_length);
	return 0;
}

size_t ether_write_frame(uint8_t buf[60], size_t buflen,
			 const uint8_t dst_mac[6], const uint8_t src_mac[6],
			 const uint16_t ethertype_host, const uint8_t *payload,
			 size_t payload_len)
{
	// Buffer and payload checks
	if (buflen < ETH_MIN_LEN || buflen < payload_len + ETH_HDR_LEN)
		return 0;
	if (payload_len > 1500)
		return 0;

	uint8_t *w = buf;

	const uint16_t ethertype_be = htons(ethertype_host);

	memcpy(w, dst_mac, 6);
	w += 6;
	memcpy(w, src_mac, 6);
	w += 6;
	memcpy(w, &ethertype_be, 2);
	w += 2;

	memcpy(w, payload, payload_len);
	w += payload_len;

	size_t total = (size_t)(w - buf);
	if (total < ETH_MIN_LEN) {
		size_t pad = ETH_MIN_LEN - total;
		memset(w, ETH_PADDING, pad);
		w += pad;
		total += pad;
	}
	return total;
}
