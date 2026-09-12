#ifndef BUILDERS_INCLUDE_H
#define BUILDERS_INCLUDE_H

#include <stdint.h>
#include <stdlib.h>

size_t make_arp(size_t count, uint16_t arp_op_le, uint8_t src_mac[6],
		uint8_t dst_mac[6], uint32_t spa_be, uint32_t tpa_be,
		uint8_t eth_frame[60]);

#endif
