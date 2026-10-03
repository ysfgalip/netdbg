#include "cmd_arp.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "../../../include/argparse.h"
#include "../../../include/arp.h"
#include "../../../include/builders.h"
#include "../../../include/ether.h"
#include "../../../include/socket.h"
#include "../../../include/utils.h"

int arp_request(struct arp arp_options, size_t interval, int count)
{
	uint8_t frame[ETH_MAX_LEN] = {0};

	size_t frame_length =
	    make_arp(1, ARP_OP_REQUEST, arp_options.sha, arp_options.tha,
		     arp_options.spa_be, arp_options.tpa_be, frame);

	int fd = create_eth_socket(ETH_P_ARP);

	size_t max = get_if_mtu(fd, arp_options.ifname);

	if (frame_length > max) {
		return -1;
	}

	for (int i = 0; count == 0 || i < count; i++) {
		int bytes_sent =
		    (int)send_eth_frame(fd, frame, frame_length,
					if_nametoindex(arp_options.ifname));
		if (bytes_sent) {
			printf("Bytes sent: %d\n", bytes_sent);
		}
		if (i == count - 1)
			break;
		delay_ms(interval);
	}

	return 0;
}

static const char *const usages[] = {
    "subcommands [options] [cmd] [args]",
    NULL,
};

int cmd_arp(int argc, const char **argv)
{
	struct arp arp_config = {
	    .string_sha = "",
	    .string_tha = "ff:ff:ff:ff:ff:ff",
	    .string_spa = "",
	    .string_tpa = "",
	    .count = 1,
	    .interval = 1000,
	};

	struct argparse_option options[] = {
	    OPT_HELP(),
	    OPT_BOOLEAN(0, "dry-run", &arp_config.dryrun,
			"show the config without sending packets"),
	    OPT_STRING('i', "interface", &arp_config.ifname,
		       "interface to use"),
	    OPT_STRING(0, "source-mac", &arp_config.string_sha,
		       "SHA to use in the ARP packet"),
	    OPT_STRING(0, "destination-mac", &arp_config.string_tha,
		       "THA to use in the ARP packet"),
	    OPT_STRING(0, "source-ip", &arp_config.string_spa,
		       "SPA to use in the ARP packet"),
	    OPT_STRING(0, "destination-ip", &arp_config.string_tpa,
		       "TPA to use in the ARP packet"),
	    OPT_INTEGER(0, "count", &arp_config.count,
			"packet count to send (0 for no limit)"),
	    OPT_INTEGER(0, "interval", &arp_config.interval,
			"interval between the packets in milliseconds"),
	    OPT_END()};

	struct argparse argparse;
	char sanitized_sha[18] = {0};
	char sanitized_tha[18] = {0};
	argparse_init(&argparse, options, usages, 0);
	argc = argparse_parse(&argparse, argc, argv);

	if (arp_config.ifname == NULL || strlen(arp_config.ifname) > IFNAMSIZ) {
		fprintf(stderr, "%s: Provide a valid interface name\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	if (arp_config.string_sha[0] == '\0') {
		if (get_ifmac(arp_config.ifname, arp_config.sha) == -1) {
			fprintf(stderr,
				"%s: Make sure that you have "
				"provided a valid "
				"ifname\n",
				argv[0]);
			return EXIT_FAILURE;
		}
	} else if (sanitize_mac(arp_config.string_sha,
				strlen(arp_config.string_sha), arp_config.sha,
				sizeof(arp_config.sha)) != 6) {
		fprintf(stderr,
			"%s: Please provide MACs in the "
			"correct format "
			"(XX:XX:XX:XX:XX:XX)\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	if (sanitize_mac(arp_config.string_tha, strlen(arp_config.string_tha),
			 arp_config.tha, sizeof(arp_config.tha)) != 6) {
		fprintf(stderr,
			"%s: Please provide MACs in the "
			"correct format "
			"(XX:XX:XX:XX:XX:XX)\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	// Set the strings again from the sanitized mac to show most accurate
	// config
	if (mac_to_string(sanitized_sha, arp_config.sha) != 17) {
		fprintf(stderr,
			"%s: Error getting the MAC Address of the "
			"interface %s\n",
			argv[0], arp_config.ifname);
		return EXIT_FAILURE;
	}
	if (mac_to_string(sanitized_tha, arp_config.tha) != 17) {
		fprintf(stderr, "%s: Error writing the destination MAC",
			argv[0]);
		return EXIT_FAILURE;
	}
	arp_config.string_sha = sanitized_sha;
	arp_config.string_tha = sanitized_tha;

	// IP strings are set from the integers to get the actual used value
	inet_pton(AF_INET, arp_config.string_spa, &arp_config.spa_be);
	arp_config.string_spa = malloc(16 * sizeof(char));
	inet_ntop(AF_INET, &arp_config.spa_be, arp_config.string_spa, 16);
	inet_pton(AF_INET, arp_config.string_tpa, &arp_config.tpa_be);
	arp_config.string_tpa = malloc(16 * sizeof(char));
	inet_ntop(AF_INET, &arp_config.tpa_be, arp_config.string_tpa, 16);

	if (arp_config.dryrun) {
		printf("Source MAC: %s\nDestination MAC: %s\nSource IP: "
		       "%s\nDestination IP: %s\n",
		       arp_config.string_sha, arp_config.string_tha,
		       arp_config.string_spa, arp_config.string_tpa);

		return 0;
	}

	if (arp_config.interval < 0) {
		fprintf(stderr, "%s: Interval must be a positive integer\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	if (arp_config.count < 0) {
		fprintf(
		    stderr,
		    "%s: count must be a positive integer (0 for no limit)\n",
		    argv[0]);
		return EXIT_FAILURE;
	}

	if (arp_request(arp_config, arp_config.interval, arp_config.count)) {
		fprintf(stderr, "%s: Error sending the ARP request\n", argv[0]);
		return EXIT_FAILURE;
	}

	return 0;
}
