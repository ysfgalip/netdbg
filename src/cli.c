#include <argp.h>
#include <arpa/inet.h>
#include <asm-generic/errno.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include "../include/argparse.h"
#include "../include/arp.h"
#include "../include/builders.h"
#include "../include/ether.h"
#include "../include/socket.h"
#include "../include/utils.h"

#define MUST_BE_ARRAY(a)                                                       \
	(0 * sizeof(struct {                                                   \
		 int : -!!__builtin_types_compatible_p(typeof(a),              \
						       typeof(&(a)[0]));       \
	 }))

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]) + MUST_BE_ARRAY(a))

#define ARP_TIMEOUT_MS 1000
#define ARP_ATTEMPT_MS 250

struct arp {
	char *string_sha, *string_tha, *string_spa, *string_tpa, *ifname;
	uint8_t sha[6], tha[6];
	uint32_t spa_be, tpa_be;
	int dryrun;
};

struct cmd_struct {
	char *cmd;
	int (*fn)(int, const char **);
};

static const char *const usages[] = {
    "subcommands [options] [cmd] [args]",
    NULL,
};

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

	for (int i = 0; i < count; i++) {
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

int cmd_arp(int argc, const char **argv)
{
	struct arp arp_config = {
	    .string_sha = "",
	    .string_tha = "ff:ff:ff:ff:ff:ff",
	    .string_spa = "",
	    .string_tpa = "",
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

	if (arp_request(arp_config, 0, 1)) {
		fprintf(stderr, "%s: Error sending the ARP request\n", argv[0]);
		return EXIT_FAILURE;
	}

	return 0;
}

static struct cmd_struct commands[] = {{"arp", cmd_arp}};

int main(int argc, const char **argv)
{
	struct argparse argparse;
	struct argparse_option options[] = {OPT_HELP(), OPT_END()};

	argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);

	argc = argparse_parse(&argparse, argc, argv);
	if (argc < 1) {
		argparse_usage(&argparse);
		return -1;
	}

	/* Try to run command with args provided. */
	struct cmd_struct *cmd = NULL;
	for (int i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!strcmp(commands[i].cmd, argv[0])) {
			cmd = &commands[i];
		}
	}
	if (cmd) {
		return cmd->fn(argc, argv);
	}
	return 0;
}

// TODO: Rename variables to *_be (big endian) and *_le (little endian) for
// clarity
int get_target_mac(uint32_t tpa_be, uint32_t spa_be, uint8_t sha[6],
		   int ifindex, uint8_t out_mac[6])
{
	uint8_t buf_recv_send[60];
	uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	if (make_arp(0, ARP_OP_REQUEST, sha, broadcast, spa_be, tpa_be,
		     buf_recv_send) != ARP_LEN)
		return -errno;
	int fd = create_eth_socket(ETH_P_ARP);
	if (fd < 0)
		return -errno;

	uint64_t start = now_ms();
	uint64_t deadline = start + ARP_TIMEOUT_MS;
	uint64_t attempt_end = 0;
	int rc = -ETIMEDOUT;

	for (;;) {
		uint64_t now = now_ms();
		if (now >= deadline)
			break;

		if (now >= attempt_end) {

			if (send_eth_frame(fd, buf_recv_send, 60, ifindex) <
			    0) {
				rc = -errno;
				break;
			}
			attempt_end = now + ARP_ATTEMPT_MS;
			if (attempt_end >= deadline)
				attempt_end = deadline;
		}
		uint8_t buf_recv[ETH_MAX_LEN];

		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		int timeout = (int)attempt_end - now;
		int n = poll(&pfd, 1, timeout);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			rc = -errno;
			break;
		}

		ssize_t eth_size =
		    recv(fd, &buf_recv, sizeof(buf_recv), MSG_TRUNC);
		if (eth_size != sizeof(buf_recv)) {
			return 1;
		}

		struct ethhdr ether_received = {0};
		size_t header_length =
		    ether_parse(&ether_received, buf_recv, eth_size);

		struct arp_packet arp_received = {0};
		arp_parse(buf_recv + header_length, eth_size - ETH_HDR_LEN,
			  &arp_received);

		if (arp_received.op != ARPOP_REPLY)
			continue;

		if (arp_received.spa_be != tpa_be ||
		    arp_received.tpa_be != spa_be)
			continue;

		memcpy(out_mac, arp_received.sha, 6);
		rc = 0;
		break;
	}

	return rc;
}
