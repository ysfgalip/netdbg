#ifndef SOCKET_INCLUDE_H
#define SOCKET_INCLUDE_H

#include <stdint.h>
#include <stdlib.h>

int create_eth_socket(uint16_t eth_protoh);

ssize_t send_eth_frame(int fd, const uint8_t *eth_frame, size_t len,
		       int ifindex);

#endif
