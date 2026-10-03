#ifndef CMD_ARP_INCLUDE_H
#define CMD_ARP_INCLUDE_H

#include <stddef.h>
#include <stdint.h>

struct arp {
	char *string_sha, *string_tha, *string_spa, *string_tpa, *ifname;
	uint8_t sha[6], tha[6];
	uint32_t spa_be, tpa_be;
	int dryrun, interval, count;
};

int arp_request(struct arp arp_options, size_t interval, int count);

int cmd_arp(int argc, const char **argv);

#endif
