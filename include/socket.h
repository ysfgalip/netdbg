#ifndef SOCKET_INCLUDE_H
#define SOCKET_INCLUDE_H

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <errno.h>

int create_eth_socket(uint16_t eth_protoh);
ssize_t send_eth_frame(int fd, const uint8_t* eth_frame, size_t len, const uint8_t* dest_mac, int ifindex);

#endif
