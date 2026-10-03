#include <argp.h>
#include <arpa/inet.h>
#include <asm-generic/errno.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include "../include/argparse.h"
#include "./commands/arp/cmd_arp.h"

#define MUST_BE_ARRAY(a)                                                       \
	(0 * sizeof(struct {                                                   \
		 int : -!!__builtin_types_compatible_p(typeof(a),              \
						       typeof(&(a)[0]));       \
	 }))

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]) + MUST_BE_ARRAY(a))

struct cmd_struct {
	char *cmd;
	int (*fn)(int, const char **);
};

static const char *const usages[] = {
    "subcommands [options] [cmd] [args]",
    NULL,
};

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
