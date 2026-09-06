#include "../include/builders.h"
#include "../include/arp.h"
#include "../include/ether.h"
#include <stdint.h>
#include <stdio.h>

int make_arp(size_t count, uint16_t arp_op, uint8_t src_mac[6],
	     uint8_t dst_mac[6], uint32_t spa, uint32_t tpa,
	     uint8_t eth_frame[60])
{
	uint8_t arp_pkt[28];
	size_t arp_size =
	    arp_write_request(arp_pkt, 28, arp_op, src_mac, spa, dst_mac, tpa);
	if (arp_size != 28) {
		return -1;
	}

	size_t eth_size = ether_write_frame(eth_frame, 60, dst_mac, src_mac,
					    ETHERTYPE_ARP, arp_pkt, arp_size);
	if (eth_size < ETH_MIN_LEN) {
		return -1;
	}
	printf("%zu", eth_size);

	/* Implemented sw else but not sure
	    int ifindex = if_nametoindex(ifname);
	    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	    if(count == -2){
		while (1) {
		    ssize_t pkt = send_eth_frame(fd, eth_frame, eth_size,
	   dst_mac, ifindex);
		}
	    }
	    ssize_t pkt = send_eth_frame(fd, eth_frame, eth_size, dst_mac,
	   ifindex);
	*/
	return 0;
}
