/* ip.access nanoBTS configuration tool */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <time.h>
#include <talloc.h>
#include <errno.h>

#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/bsc/gsm_data.h>

static struct {
	const char *ifname;
	const char *bind_ip;
	int send_interval;
	bool list_view;
	time_t list_view_timeout;
	bool format_json;
	bool long_names;
} cmdline_opts = {
	.ifname = NULL,
	.bind_ip = NULL,
	.send_interval = 5,
	.list_view = false,
	.list_view_timeout = 10,
	.format_json = false,
	.long_names = false,
};

static void print_help()
{
	printf("\n");
	printf("Usage: abisip-find [-l] [<interface-name>]\n");
	printf("  <interface-name>  Specify the outgoing network interface,\n"
	       "                    e.g. 'eth0'\n");
	printf("  -b --bind-ip <ip> Specify the local IP to bind to,\n"
	       "                    e.g. '192.168.1.10'\n");
	printf("  -i --interval <s> Send broadcast frames every <s> seconds.\n");
	printf("  -l --list-view    Instead of printing received responses,\n"
	       "                    output a sorted list of currently present\n"
	       "                    base stations and change events.\n");
	printf("  -t --timeout <s>  Drop base stations after <s> seconds of\n"
	       "                    receiving no more replies from it.\n"
	       "                    Implies --list-view.\n");
	printf("  -j --format-json  Print BTS information using json syntax.\n");
	printf("  -L --long-labels  More verbose CCM value labels\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"bind-ip", 1, 0, 'b'},
			{"send-interval", 1, 0, 'i'},
			{"list-view", 0, 0, 'l'},
			{"timeout", 1, 0, 't'},
			{"format-json", 0, 0, 'j'},
			{"long-labels", 0, 0, 'L'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hb:i:lt:jL",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		case 'b':
			cmdline_opts.bind_ip = optarg;
			break;
		case 'i':
			errno = 0;
			cmdline_opts.send_interval = strtoul(optarg, NULL, 10);
			if (errno || cmdline_opts.send_interval < 1) {
				fprintf(stderr, "Invalid interval value: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 't':
			errno = 0;
			cmdline_opts.list_view_timeout = strtoul(optarg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid timeout value: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			/* fall through to imply list-view: */
		case 'l':
			cmdline_opts.list_view = true;
			break;
		case 'j':
			cmdline_opts.format_json = true;
			break;
		case 'L':
			cmdline_opts.long_names = true;
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting. Try --help.\n");
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (argc - optind > 0)
		cmdline_opts.ifname = argv[optind++];

	if (argc - optind > 0) {
		fprintf(stderr, "Error: too many arguments\n");
		print_help();
		exit(EXIT_FAILURE);
	}
}

static int udp_sock(const char *ifname, const char *bind_ip)
{
	int fd, rc, bc = 1;
	struct sockaddr_in sa;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return fd;

	if (ifname) {
#ifdef __FreeBSD__
		rc = setsockopt(fd, SOL_SOCKET, IP_RECVIF, ifname,
				strlen(ifname));
#else
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
				strlen(ifname));
#endif
		if (rc < 0)
			goto err;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(3006);
	if (bind_ip) {
		rc = inet_pton(AF_INET, bind_ip, &sa.sin_addr);
		if (rc != 1) {
			fprintf(stderr, "bind ip addr: inet_pton failed, returned %d\n", rc);
			goto err;
		}
	} else {
		sa.sin_addr.s_addr = INADDR_ANY;
	}

	rc = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0)
		goto err;

	rc = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bc, sizeof(bc));
	if (rc < 0)
		goto err;

#if 0
	/* we cannot bind, since the response packets don't come from
	 * the broadcast address */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(3006);
	inet_aton("255.255.255.255", &sa.sin_addr);

	rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0)
		goto err;
#endif
	return fd;

err:
	close(fd);
	return rc;
}

const unsigned char find_pkt[] = { 0x00, 0x0b+8, IPAC_PROTO_IPACCESS, 0x00,
				IPAC_MSGT_ID_GET,
					0x01, IPAC_IDTAG_MACADDR,
					0x01, IPAC_IDTAG_IPADDR,
					0x01, IPAC_IDTAG_UNIT,
					0x01, IPAC_IDTAG_LOCATION1,
					0x01, IPAC_IDTAG_LOCATION2,
					0x01, IPAC_IDTAG_EQUIPVERS,
					0x01, IPAC_IDTAG_SWVERSION,
					0x01, IPAC_IDTAG_UNITNAME,
					0x01, IPAC_IDTAG_SERNR,
				};


static int bcast_find(int fd)
{
	struct sockaddr_in sa;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(3006);
	inet_aton("255.255.255.255", &sa.sin_addr);

	return sendto(fd, find_pkt, sizeof(find_pkt), 0, (struct sockaddr *) &sa, sizeof(sa));
}

static const char *ipa_ccm_idtag_short_names[] = {
	[IPAC_IDTAG_SERNR]	= "serno",
	[IPAC_IDTAG_UNITNAME]	= "Name",
	[IPAC_IDTAG_LOCATION1]	= "Loc1",
	[IPAC_IDTAG_LOCATION2]	= "Loc2",
	[IPAC_IDTAG_EQUIPVERS]	= "Equip",
	[IPAC_IDTAG_SWVERSION]	= "Softw",
	[IPAC_IDTAG_IPADDR]	= "IP",
	[IPAC_IDTAG_MACADDR]	= "MAC",
	[IPAC_IDTAG_UNIT]	= "Unit",
};

static const char *ipa_ccm_idtag_short_name(uint8_t tag)
{
	if (tag >= ARRAY_SIZE(ipa_ccm_idtag_short_names))
		return "unknown";

	return ipa_ccm_idtag_short_names[tag];
}

static const char *idtag_name(uint8_t tag)
{
	if (cmdline_opts.long_names)
		return ipa_ccm_idtag_name(tag);
	return ipa_ccm_idtag_short_name(tag);
}

static char *parse_response(void *ctx, unsigned char *buf, int len)
{
	unsigned int out_len;
	uint8_t t_len;
	uint8_t t_tag;
	uint8_t *cur = buf;
	char *out = talloc_zero_size(ctx, 512);

	if (cmdline_opts.format_json)
		out = talloc_asprintf_append(out,"{ ");

	while (cur < buf + len) {
		t_len = *cur++;
		t_tag = *cur++;

		if (cmdline_opts.format_json)
			out = talloc_asprintf_append(out, "\"%s\": \"%s\", ", idtag_name(t_tag), cur);
		else
			out = talloc_asprintf_append(out, "%s='%s'  ", idtag_name(t_tag), cur);

		cur += t_len;
	}

	if (cmdline_opts.format_json) {
		out_len = strlen(out);
		if (out[out_len-2] == ',')
			out[out_len-2] = ' ';
		out[out_len-1] = '}';
	}

	return out;
}

struct base_station {
	struct llist_head entry;
	char *line;
	time_t timestamp;
};

LLIST_HEAD(base_stations);

void *ctx = NULL;

void print_timestamp()
{
	time_t now = time(NULL);
	printf("\n\n----- %s\n", ctime(&now));
}

struct base_station *base_station_parse(unsigned char *buf, int len)
{
	struct base_station *new_bs = talloc_zero(ctx, struct base_station);
	new_bs->line = parse_response(new_bs, buf, len);
	new_bs->timestamp = time(NULL);
	return new_bs;
}

bool base_stations_add(struct base_station *new_bs)
{
	struct base_station *bs;

	llist_for_each_entry(bs, &base_stations, entry) {
		int c = strcmp(new_bs->line, bs->line);
		if (!c) {
			/* entry already exists. */
			bs->timestamp = new_bs->timestamp;
			return false;
		}

		if (c < 0) {
			/* found the place to add the entry */
			break;
		}
	}

	print_timestamp();
	printf("New:\n%s\n", new_bs->line);

	llist_add_tail(&new_bs->entry, &bs->entry);
	return true;
}

bool base_stations_timeout()
{
	struct base_station *bs, *next_bs;
	time_t now = time(NULL);
	bool changed = false;

	llist_for_each_entry_safe(bs, next_bs, &base_stations, entry) {
		if (now - bs->timestamp < cmdline_opts.list_view_timeout)
			continue;
		print_timestamp();
		printf("LOST:\n%s\n", bs->line);

		llist_del(&bs->entry);
		talloc_free(bs);
		changed = true;
	}
	return changed;
}

void base_stations_print()
{
	struct base_station *bs;
	int count = 0;

	print_timestamp();
	if (cmdline_opts.format_json)
		printf("[");

	llist_for_each_entry(bs, &base_stations, entry) {
		if (cmdline_opts.format_json) {
			if (count)
				printf(",");
			printf("\n%s", bs->line);
		} else {
			printf("%3d: %s\n", count, bs->line);
		}
		count++;
	}

	if (cmdline_opts.format_json)
		printf("%c]\n", count ? '\n': ' ');

	printf("\nTotal: %d\n", count);
}

static void base_stations_bump(bool known_changed)
{
	bool changed = known_changed;
	if (base_stations_timeout())
		changed = true;

	if (changed)
		base_stations_print();
}

static void handle_response(unsigned char *buf, int len)
{
	static unsigned int responses = 0;
	responses++;

	if (cmdline_opts.list_view) {
		bool changed = false;
		struct base_station *bs = base_station_parse(buf, len);
		if (base_stations_add(bs))
			changed = true;
		else
			talloc_free(bs);
		base_stations_bump(changed);
		printf("RX: %u   \r", responses);
	} else {
		printf("%s\n", parse_response(ctx, buf, len));
	}
	fflush(stdout);
}

static int read_response(int fd)
{
	unsigned char buf[255];
	struct sockaddr_in sa;
	int len;
	socklen_t sa_len = sizeof(sa);

	len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &sa_len);
	if (len < 0)
		return len;

	/* 2 bytes length, 1 byte protocol */
	if (buf[2] != IPAC_PROTO_IPACCESS)
		return 0;

	if (buf[4] != IPAC_MSGT_ID_RESP)
		return 0;

	handle_response(buf+6, len-6);
	return 0;
}

static int bfd_cb(struct osmo_fd *bfd, unsigned int flags)
{
	if (flags & BSC_FD_READ)
		return read_response(bfd->fd);
	if (flags & BSC_FD_WRITE) {
		bfd->when &= ~BSC_FD_WRITE;
		return bcast_find(bfd->fd);
	}
	return 0;
}

static struct osmo_timer_list timer;

static void timer_cb(void *_data)
{
	struct osmo_fd *bfd = _data;

	bfd->when |= BSC_FD_WRITE;

	base_stations_bump(false);

	osmo_timer_schedule(&timer, cmdline_opts.send_interval, 0);
}

int main(int argc, char **argv)
{
	struct osmo_fd bfd;
	int rc;

	printf("abisip-find (C) 2009-2010 by Harald Welte\n");
	printf("            (C) 2017 by sysmocom - s.f.m.c. GmbH\n");
	printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");

	handle_options(argc, argv);

	if (!cmdline_opts.ifname && !cmdline_opts.bind_ip)
		fprintf(stdout, "- You might need to specify the outgoing network interface,\n"
			"  e.g. ``%s eth0'' (requires root permissions),\n"
			"  or alternatively use -b to bind to the source address\n"
			"  assigned to that interface\n", argv[0]);
	if (!cmdline_opts.list_view)
		fprintf(stdout, "- You may find the --list-view option convenient.\n");
	else if (cmdline_opts.send_interval >= cmdline_opts.list_view_timeout)
		fprintf(stdout, "\nWARNING: the --timeout should be larger than --interval.\n\n");

	bfd.cb = bfd_cb;
	bfd.when = BSC_FD_READ | BSC_FD_WRITE;
	bfd.fd = udp_sock(cmdline_opts.ifname, cmdline_opts.bind_ip);
	if (bfd.fd < 0) {
		perror("Cannot create local socket for broadcast udp");
		exit(1);
	}

	rc = osmo_fd_register(&bfd);
	if (rc < 0) {
		fprintf(stderr, "Cannot register FD\n");
		exit(1);
	}

	osmo_timer_setup(&timer, timer_cb, &bfd);
	osmo_timer_schedule(&timer, cmdline_opts.send_interval, 0);

	printf("Trying to find ip.access BTS by broadcast UDP...\n");

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}

