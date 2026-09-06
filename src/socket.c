#include "../include/socket.h"

int create_eth_socket(uint16_t eth_protoh)
{
	int fd = socket(AF_PACKET, SOCK_RAW, htons(eth_protoh));
	return fd;
}

ssize_t send_eth_frame(int fd, const uint8_t *eth_frame, size_t len,
		       const uint8_t *dest_mac, int ifindex)
{
	if (fd < 0 || !eth_frame || len == 0 || ifindex <= 0) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_ll saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ALL);
	saddr.sll_ifindex = ifindex;
	saddr.sll_halen = ETH_ALEN;
	memcpy(saddr.sll_addr, dest_mac, 6);

	return sendto(fd, eth_frame, len, 0, (const struct sockaddr *)&saddr,
		      sizeof(saddr));
}
