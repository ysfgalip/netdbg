#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>

#include "../include/utils.h"

// Gives the monotonic time in milliseconds
uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Converts a given str of a hex number to uint8_t array
void hextoint(const char *hex, size_t length, uint8_t *hex_int)
{
	for (size_t i = 0; i < length; ++i) {
		char temp[3] = {hex[i * 2], hex[i * 2 + 1], 0};
		hex_int[i] = (uint8_t)strtoul(temp, NULL, 16);
	}
}

static int hexval(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

int mac_to_string(char *mac_out, const uint8_t mac_in[6])
{
	return sprintf(mac_out, "%02X:%02X:%02X:%02X:%02X:%02X", mac_in[0],
		       mac_in[1], mac_in[2], mac_in[3], mac_in[4], mac_in[5]);
}

// Better input validation for future but ok for now
int sanitize_mac(const char *mac_nonsanitized, size_t in_length,
		 uint8_t out_mac[6], size_t out_length)
{
	if (in_length != 17) {
		return -1;
	}
	if (out_length < 6) {
		return -2;
	}
	uint8_t temp_mac[6];
	size_t sanitized_count = 0;
	for (size_t i = 0; i < in_length; i += 3) {

		if (i + 2 < in_length && mac_nonsanitized[i + 2] != ':')
			return -3;

		int H = mac_nonsanitized[i];
		int L = mac_nonsanitized[i + 1];
		int h = hexval(H);
		int l = hexval(L);
		if (h < 0 || l < 0)
			return -3;
		temp_mac[sanitized_count++] = (uint8_t)(h << 4) | l;
	}
	memcpy(out_mac, temp_mac, 6);
	return sanitized_count;
}

int get_ifmac(const char *ifname, uint8_t mac_out[6])
{
	if (!ifname || !mac_out) {
		return -1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);

	memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

int arp_lookup_local(uint32_t tpa_be, const char *ifname, uint8_t mac[6])
{
	struct arpreq req = {0};
	struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;

	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = tpa_be;
	strncpy(req.arp_dev, ifname, sizeof(req.arp_dev) - 1);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	int rc = ioctl(fd, SIOCGARP, &req);
	close(fd);

	if (rc < 0 || !(req.arp_flags & ATF_COM))
		return -1; /* missing or incomplete */
	memcpy(mac, req.arp_ha.sa_data, 6);
	return 0;
}
