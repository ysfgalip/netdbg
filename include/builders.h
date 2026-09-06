#ifndef BUILDERS_INCLUDE_H
#define BUILDERS_INCLUDE_H

#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

int make_arp(size_t count, uint16_t arp_op, uint8_t src_mac[6],
             uint8_t dst_mac[6], uint32_t spa, uint32_t tpa,
             uint8_t eth_frame[60]);

#endif
