/* Test the neighbor_ident.h API */
/*
 * (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <talloc.h>
#include <stdio.h>
#include <errno.h>

#include <osmocom/gsm/gsm0808.h>

#include <osmocom/bsc/neighbor_ident.h>

struct neighbor_ident_list *nil;

static const struct neighbor_ident_key *k(int from_bts, uint16_t arfcn, enum bsic_kind kind, uint16_t bsic)
{
	static struct neighbor_ident_key key;
	key = (struct neighbor_ident_key){
		.from_bts = from_bts,
		.arfcn = arfcn,
		.bsic_kind = kind,
		.bsic = bsic,
	};
	return &key;
}

static const struct gsm0808_cell_id_list2 cgi1 = {
	.id_discr = CELL_IDENT_WHOLE_GLOBAL,
	.id_list_len = 1,
	.id_list = {
		{
			.global = {
				.lai = {
					.plmn = { .mcc = 1, .mnc = 2, .mnc_3_digits = false },
					.lac = 3,
				},
				.cell_identity = 4,
			}
		},
	},
};

static const struct gsm0808_cell_id_list2 cgi2 = {
	.id_discr = CELL_IDENT_WHOLE_GLOBAL,
	.id_list_len = 2,
	.id_list = {
		{
			.global = {
				.lai = {
					.plmn = { .mcc = 1, .mnc = 2, .mnc_3_digits = false },
					.lac = 3,
				},
				.cell_identity = 4,
			}
		},
		{
			.global = {
				.lai = {
					.plmn = { .mcc = 5, .mnc = 6, .mnc_3_digits = true },
					.lac = 7,
				},
				.cell_identity = 8,
			}
		},
	},
};

static const struct gsm0808_cell_id_list2 lac1 = {
	.id_discr = CELL_IDENT_LAC,
	.id_list_len = 1,
	.id_list = {
		{
			.lac = 123
		},
	},
};

static const struct gsm0808_cell_id_list2 lac2 = {
	.id_discr = CELL_IDENT_LAC,
	.id_list_len = 2,
	.id_list = {
		{
			.lac = 456
		},
		{
			.lac = 789
		},
	},
};

void print_cil(const struct gsm0808_cell_id_list2 *cil)
{
	unsigned int i;
	if (!cil) {
		printf("     cell_id_list == NULL\n");
		return;
	}
	switch (cil->id_discr) {
	case CELL_IDENT_WHOLE_GLOBAL:
		printf("     cell_id_list cgi[%u] = {\n", cil->id_list_len);
		for (i = 0; i < cil->id_list_len; i++)
			printf("       %2d: %s\n", i, osmo_cgi_name(&cil->id_list[i].global));
		printf("     }\n");
		break;
	case CELL_IDENT_LAC:
		printf("     cell_id_list lac[%u] = {\n", cil->id_list_len);
		for (i = 0; i < cil->id_list_len; i++)
			printf("      %2d: %u\n", i, cil->id_list[i].lac);
		printf("     }\n");
		break;
	default:
		printf("     Unimplemented id_disc\n");
	}
}

static int print_nil_i;

bool nil_cb(const struct neighbor_ident_key *key, const struct gsm0808_cell_id_list2 *val,
	    void *cb_data)
{
	printf(" %2d: %s\n", print_nil_i++, neighbor_ident_key_name(key));
	print_cil(val);
	return true;
}

void print_nil()
{
	print_nil_i = 0;
	neighbor_ident_iter(nil, nil_cb, NULL);
	if (!print_nil_i)
		printf("     (empty)\n");
}

#define check_add(key, val, expect_rc) \
	do { \
		int rc; \
		rc = neighbor_ident_add(nil, key, val); \
		printf("neighbor_ident_add(" #key ", " #val ") --> expect rc=" #expect_rc ", got %d\n", rc); \
		if (rc != expect_rc) \
			printf("ERROR\n"); \
		print_nil(); \
	} while(0)

#define check_del(key, expect_rc) \
	do { \
		bool rc; \
		rc = neighbor_ident_del(nil, key); \
		printf("neighbor_ident_del(" #key ") --> %s\n", rc ? "entry deleted" : "nothing deleted"); \
		if (rc != expect_rc) \
			printf("ERROR: expected: %s\n", expect_rc ? "entry deleted" : "nothing deleted"); \
		print_nil(); \
	} while(0)

#define check_get(key, expect_rc) \
	do { \
		const struct gsm0808_cell_id_list2 *rc; \
		rc = neighbor_ident_get(nil, key); \
		printf("neighbor_ident_get(" #key ") --> %s\n", \
		       rc ? "entry returned" : "NULL"); \
		if (((bool)expect_rc) != ((bool) rc)) \
			printf("ERROR: expected %s\n", expect_rc ? "an entry" : "NULL"); \
		if (rc) \
			print_cil(rc); \
	} while(0)

int main(void)
{
	void *ctx = talloc_named_const(NULL, 0, "neighbor_ident_test");

	printf("\n--- testing NULL neighbor_ident_list\n");
	nil = NULL;
	check_add(k(0, 1, BSIC_6BIT, 2), &cgi1, -ENOMEM);
	check_get(k(0, 1, BSIC_6BIT, 2), false);
	check_del(k(0, 1, BSIC_6BIT, 2), false);

	printf("\n--- adding entries, test that no two identical entries are added\n");
	nil = neighbor_ident_init(ctx);
	check_add(k(0, 1, BSIC_6BIT, 2), &cgi1, 1);
	check_get(k(0, 1, BSIC_6BIT, 2), true);
	check_add(k(0, 1, BSIC_6BIT, 2), &cgi1, 1);
	check_add(k(0, 1, BSIC_6BIT, 2), &cgi2, 2);
	check_add(k(0, 1, BSIC_6BIT, 2), &cgi2, 2);
	check_del(k(0, 1, BSIC_6BIT, 2), true);

	printf("\n--- Cannot mix cell identifier types for one entry\n");
	check_add(k(0, 1, BSIC_6BIT, 2), &cgi1, 1);
	check_add(k(0, 1, BSIC_6BIT, 2), &lac1, -EINVAL);
	check_del(k(0, 1, BSIC_6BIT, 2), true);
	neighbor_ident_free(nil);

	printf("\n--- BTS matching: specific BTS is stronger\n");
	nil = neighbor_ident_init(ctx);
	check_add(k(NEIGHBOR_IDENT_KEY_ANY_BTS, 1, BSIC_6BIT, 2), &lac1, 1);
	check_add(k(3, 1, BSIC_6BIT, 2), &lac2, 2);
	check_get(k(2, 1, BSIC_6BIT, 2), true);
	check_get(k(3, 1, BSIC_6BIT, 2), true);
	check_get(k(4, 1, BSIC_6BIT, 2), true);
	check_get(k(NEIGHBOR_IDENT_KEY_ANY_BTS, 1, BSIC_6BIT, 2), true);
	neighbor_ident_free(nil);

	printf("\n--- BSIC matching: 6bit and 9bit are different realms, and wildcard match is weaker\n");
	nil = neighbor_ident_init(ctx);
	check_add(k(0, 1, BSIC_NONE, 0), &cgi1, 1);
	check_add(k(0, 1, BSIC_6BIT, 2), &lac1, 1);
	check_add(k(0, 1, BSIC_9BIT, 2), &lac2, 2);
	check_get(k(0, 1, BSIC_6BIT, 2), true);
	check_get(k(0, 1, BSIC_9BIT, 2), true);
	printf("--- wildcard matches both 6bit and 9bit BSIC regardless:\n");
	check_get(k(0, 1, BSIC_6BIT, 23), true);
	check_get(k(0, 1, BSIC_9BIT, 23), true);
	neighbor_ident_free(nil);

	printf("\n--- Value ranges\n");
	nil = neighbor_ident_init(ctx);
	check_add(k(0, 6, BSIC_6BIT, 1 << 6), &lac1, -ERANGE);
	check_add(k(0, 9, BSIC_9BIT, 1 << 9), &lac1, -ERANGE);
	check_add(k(0, 6, BSIC_6BIT, -1), &lac1, -ERANGE);
	check_add(k(0, 9, BSIC_9BIT, -1), &lac1, -ERANGE);
	check_add(k(NEIGHBOR_IDENT_KEY_ANY_BTS - 1, 1, BSIC_NONE, 1), &cgi2, -ERANGE);
	check_add(k(256, 1, BSIC_NONE, 1), &cgi2, -ERANGE);
	check_add(k(0, 0, BSIC_NONE, 0), &cgi1, 1);
	check_add(k(255, 65535, BSIC_NONE, 65535), &lac1, 1);
	check_add(k(0, 0, BSIC_6BIT, 0), &cgi2, 2);
	check_add(k(255, 65535, BSIC_6BIT, 0x3f), &lac2, 2);
	check_add(k(0, 0, BSIC_9BIT, 0), &cgi1, 1);
	check_add(k(255, 65535, BSIC_9BIT, 0x1ff), &cgi2, 2);

	neighbor_ident_free(nil);

	printf("\n--- size limits\n");
	{
		int i;
		struct gsm0808_cell_id_list2 a = { .id_discr = CELL_IDENT_LAC };
		struct gsm0808_cell_id_list2 b = {
			.id_discr = CELL_IDENT_LAC,
			.id_list = {
				{ .lac = 423 }
			},
			.id_list_len = 1,
		};
		for (i = 0; i < ARRAY_SIZE(a.id_list); i++) {
			a.id_list[a.id_list_len ++].lac = i;
		}

		nil = neighbor_ident_init(ctx);

		i = neighbor_ident_add(nil, k(0, 1, BSIC_6BIT, 2), &a);
		printf("Added first cell identifier list (added %u) --> rc = %d\n", a.id_list_len, i);
		i = neighbor_ident_add(nil, k(0, 1, BSIC_6BIT, 2), &b);
		printf("Added second cell identifier list (tried to add %u) --> rc = %d\n", b.id_list_len, i);
		if (i != -ENOSPC)
			printf("ERROR: expected rc=%d\n", -ENOSPC);
		neighbor_ident_free(nil);
	}

	OSMO_ASSERT(talloc_total_blocks(ctx) == 1);
	talloc_free(ctx);

	return 0;
}
