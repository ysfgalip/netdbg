#include <net/ethernet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../include/arp.h"
#include "../include/builders.h"
#include "../include/ether.h"

size_t make_arp(size_t count, uint16_t arp_op, uint8_t sha[6], uint8_t tha[6],
		uint32_t spa, uint32_t tpa, uint8_t eth_frame[60])
{
	uint8_t packet[28] = {0};

	size_t arp_size = arp_build(packet, arp_op, sha, tha, spa, tpa);
	if (arp_size != ARP_LEN) {
		return -1;
	}

	struct ethhdr ethernet_header = {0};
	size_t eth_header_size =
	    ether_build(&ethernet_header, tha, sha, ETHERTYPE_ARP);
	if (eth_header_size != ETH_HDR_LEN) {
		return -2;
	}

	uint8_t temp_frame[60] = {0};
	size_t eth_size =
	    ether_build_frame(temp_frame, &ethernet_header, (uint8_t *)&packet,
			      arp_size, ETH_MAX_LEN);
	if (eth_size != ETH_MIN_LEN) {
		return -3;
	}

	memcpy(eth_frame, temp_frame, eth_size);

	return eth_size;
}
