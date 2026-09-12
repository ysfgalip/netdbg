#include <memory.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "../include/arp.h"

size_t arp_parse(const uint8_t *buf, size_t buflen, struct arp_packet *out)
{
	if (buflen != ARP_LEN + ARP_PAD_LEN) {
		return 0;
	}

	struct arp_packet temp = {0};
	const uint8_t *w = buf;

	// Verification stuff
	memcpy(&temp.hw_type, w, sizeof(temp.hw_type));
	temp.hw_type = ntohs(temp.hw_type);
	w += sizeof(temp.hw_type);
	memcpy(&temp.proto_type, w, sizeof(temp.proto_type));
	temp.proto_type = ntohs(temp.proto_type);
	w += sizeof(temp.proto_type);
	memcpy(&temp.hw_len, w, sizeof(temp.hw_len));
	w += sizeof(temp.hw_len);
	memcpy(&temp.proto_len, w, sizeof(temp.proto_len));
	w += sizeof(temp.proto_len);

	if (temp.hw_type != ARP_ETH_HTYPE ||
	    temp.proto_type != ARP_IPV4_PTYPE || temp.hw_len != ARP_HLEN_ETH ||
	    temp.proto_len != ARP_PLEN_IPV4) {
		return 0;
	}

	memcpy(&temp.op, w, sizeof(temp.op));
	temp.op = ntohs(temp.op);
	w += sizeof(temp.op);

	memcpy(&temp.sha, w, sizeof(temp.sha));
	w += sizeof(temp.sha);

	memcpy(&temp.spa_be, w, sizeof(temp.spa_be));
	w += sizeof(temp.spa_be);

	memcpy(&temp.tha, w, sizeof(temp.tha));
	w += sizeof(temp.tha);

	memcpy(&temp.tpa_be, w, sizeof(temp.tpa_be));
	w += sizeof(temp.tpa_be);

	*out = temp;
	return w - buf;
}

int arp_build(uint8_t *out, uint16_t arp_op, uint8_t sha[6], uint8_t tha[6],
	      uint32_t spa_be, uint32_t tpa_be)
{
	uint8_t *w = out;
	uint16_t htype_be = htons(ARP_ETH_HTYPE),
		 ptype_be = htons(ARP_IPV4_PTYPE), opcode_be = htons(arp_op);

	memcpy(w, &htype_be, 2);
	w += 2;
	memcpy(w, &ptype_be, 2);
	w += 2;
	*w++ = ARP_HLEN_ETH;
	*w++ = ARP_PLEN_IPV4;
	memcpy(w, &opcode_be, 2);
	w += 2;
	memcpy(w, sha, 6);
	w += 6;
	memcpy(w, &spa_be, 4);
	w += 4;
	memcpy(w, tha, 6);
	w += 6;
	memcpy(w, &tpa_be, 4);
	w += 4;

	return w - out;
}

size_t arp_write_request(uint8_t *buf, size_t buflen, const uint16_t arp_op_le,
			 const uint8_t sha[6], uint32_t spa_be,
			 const uint8_t tha[6], uint32_t tpa_be)
{
	if (buflen < ARP_LEN)
		return 0;
	uint8_t *w = buf;

	uint16_t htype_be = htons(ARP_ETH_HTYPE),
		 ptype_be = htons(ARP_IPV4_PTYPE), opcode_be = htons(arp_op_le);

	memcpy(w, &htype_be, 2);
	w += 2;
	memcpy(w, &ptype_be, 2);
	w += 2;
	*w++ = ARP_HLEN_ETH;
	*w++ = ARP_PLEN_IPV4;
	memcpy(w, &opcode_be, 2);
	w += 2;
	memcpy(w, sha, 6);
	w += 6;
	memcpy(w, &spa_be, 4);
	w += 4;
	memcpy(w, tha, 6);
	w += 6;
	memcpy(w, &tpa_be, 4);
	w += 4;

	return ARP_LEN;
}
