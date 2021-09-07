/* Manage identity of neighboring BSS cells for inter-BSC handover */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/ctrl/control_cmd.h>

#include <osmocom/bsc/gsm_data.h>

struct vty;
struct gsm_network;
struct gsm_bts;
struct gsm0808_cell_id_list2;

#define NEIGHBOR_IDENT_KEY_ANY_BTS -1

#define BSIC_ANY 0xff

enum neighbor_type {
	NEIGHBOR_TYPE_UNSET = 0,
	NEIGHBOR_TYPE_BTS_NR = 1,
	NEIGHBOR_TYPE_CELL_ID = 2,
};

/* One line of VTY neighbor configuration as entered by the user.
 * One of three variants:
 *
 * - just the local-BSS neighbor BTS nr:
 *     neighbor bts 123
 *
 * - a neighbor cell identifier *without* ARFCN+BSIC:
 *     neighbor (lac|lac-ci|cgi|cgi-ps) 1 2 3...
 *   This is an elaborate / BTS-nr-agnostic way of indicating a local-BSS neighbor cell.
 *
 * - a neighbor cell identifier *with* ARFCN+BSIC:
 *     neighbor (lac|lac-ci|cgi|cgi-ps) 1 2 3... arfcn 456 bsic (23|any)
 *   This can either be
 *   - a remote-BSS neighbor cell, or
 *   - a super elaborate way of indicating a local-BSS neighbor, if this cell id exists in the local BSS.
 */
struct neighbor {
	struct llist_head entry;

	enum neighbor_type type;
	union {
		uint8_t bts_nr;
		struct {
			struct gsm0808_cell_id id;
			bool ab_present;
			struct cell_ab ab;
		} cell_id;
	};
};

int resolve_local_neighbor(struct gsm_bts **local_neighbor_p, const struct gsm_bts *from_bts,
			   const struct neighbor *neighbor);
int resolve_remote_neighbors(struct gsm_bts *from_bts, const struct cell_ab *target_ab);

int cell_ab_to_str_buf(char *buf, size_t buflen, const struct cell_ab *cell);
char *cell_ab_to_str_c(void *ctx, const struct cell_ab *cell);

bool cell_ab_match(const struct cell_ab *entry, const struct cell_ab *search_for, bool exact_match);
bool cell_ab_valid(const struct cell_ab *cell);

int neighbor_to_str_buf(char *buf, size_t buflen, const struct neighbor *n);
char *neighbor_to_str_c(void *ctx, const struct neighbor *n);
bool neighbor_same(const struct neighbor *a, const struct neighbor *b, bool check_cell_ab);

void bts_cell_ab(struct cell_ab *arfcn_bsic, const struct gsm_bts *bts);

int resolve_neighbors(struct gsm_bts **local_neighbor_p, struct gsm0808_cell_id_list2 *remote_neighbors,
		      struct gsm_bts *from_bts, const struct cell_ab *target_ab, bool log_errors);

void neighbor_ident_vty_init();
void neighbor_ident_vty_write_bts(struct vty *vty, const char *indent, struct gsm_bts *bts);
void neighbor_ident_vty_write_network(struct vty *vty, const char *indent);

int neighbors_check_cfg();

#define CELL_AB_VTY_PARAMS "arfcn <0-1023> bsic (<0-63>|any)"
#define CELL_AB_VTY_DOC \
	"ARFCN of neighbor cell\n" "ARFCN value\n" \
	"BSIC of neighbor cell\n" "BSIC value\n" \
	"for all BSICs / use any BSIC in this ARFCN\n"
void neighbor_ident_vty_parse_arfcn_bsic(struct cell_ab *ab, const char **argv);

int neighbor_address_resolution(const struct gsm_network *net, const struct cell_ab *ab,
				uint16_t lac, uint16_t cell_id,
				struct osmo_cell_global_id_ps *res_cgi_ps);

struct ctrl_handle *neighbor_controlif_setup(struct gsm_network *net);
int neighbor_ctrl_cmds_install(struct gsm_network *net);

enum neighbor_ctrl_node {
	CTRL_NODE_NEIGH = _LAST_CTRL_NODE,
	_LAST_CTRL_NODE_NEIGHBOR
};
