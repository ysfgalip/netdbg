#ifndef UTILS_INCLUDE_H
#define UTILS_INCLUDE_H

#include <stdint.h>
#include <unistd.h>

uint64_t now_ms(void);

void hextoint(const char *hex, size_t length, uint8_t *hex_int);

int mac_to_string(char *mac_out, const uint8_t mac_in[6]);

int sanitize_mac(const char *mac_nonsanitized, size_t in_length,
		 uint8_t out_mac[6], size_t out_length);

int get_ifmac(const char *ifname, uint8_t mac_out[6]);

int arp_lookup_local(uint32_t tpa_be, const char *ifname, uint8_t mac[6]);

int get_if_mtu(const int fd, char *ifname);

#endif
