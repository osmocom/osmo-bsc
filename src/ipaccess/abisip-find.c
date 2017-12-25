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
	bool list_view;
	time_t list_view_timeout;
} cmdline_opts = {
	.ifname = NULL,
	.list_view = false,
	.list_view_timeout = 10,
};

static void print_help()
{
	printf("\n");
	printf("Usage: abisip-find [-l] [<interface-name>]\n");
	printf("  <interface-name>  Specify the outgoing network interface,\n"
	       "                    e.g. 'eth0'\n");
	printf("  -l --list-view    Instead of printing received responses,\n"
	       "                    output a sorted list of currently present\n"
	       "                    base stations and change events.\n");
	printf("  -t --timeout <s>  Drop base stations after <s> seconds of\n"
	       "                    receiving no more replies from it.\n"
	       "                    Implies --list-view.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"list-view", 0, 0, 'l'},
			{"timeout", 1, 0, 't'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hlt:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
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

static int udp_sock(const char *ifname)
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
	sa.sin_addr.s_addr = INADDR_ANY;

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

static char *parse_response(void *ctx, unsigned char *buf, int len)
{
	uint8_t t_len;
	uint8_t t_tag;
	uint8_t *cur = buf;
	char *out = talloc_zero_size(ctx, 512);

	while (cur < buf + len) {
		t_len = *cur++;
		t_tag = *cur++;
		
		out = talloc_asprintf_append(out, "%s='%s'  ", ipa_ccm_idtag_name(t_tag), cur);

		cur += t_len;
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
	llist_for_each_entry(bs, &base_stations, entry) {
		printf("%3d: %s\n", count, bs->line);
		count++;
	}
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
		fflush(stdout);
	} else {
		char *line = parse_response(ctx, buf, len);
		printf(line);
		printf("\n");
		talloc_free(line);
	}
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

	osmo_timer_schedule(&timer, 5, 0);
}

int main(int argc, char **argv)
{
	struct osmo_fd bfd;
	int rc;

	printf("abisip-find (C) 2009-2010 by Harald Welte\n");
	printf("            (C) 2017 by sysmocom - s.f.m.c. GmbH\n");
	printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");

	handle_options(argc, argv);

	if (!cmdline_opts.ifname)
		fprintf(stdout, "- You might need to specify the outgoing\n"
			"  network interface, e.g. ``%s eth0''\n", argv[0]);
	if (!cmdline_opts.list_view)
		fprintf(stdout, "- You may find the --list-view option convenient.\n");

	bfd.cb = bfd_cb;
	bfd.when = BSC_FD_READ | BSC_FD_WRITE;
	bfd.fd = udp_sock(cmdline_opts.ifname);
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
	osmo_timer_schedule(&timer, 5, 0);

	printf("Trying to find ip.access BTS by broadcast UDP...\n");

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}

