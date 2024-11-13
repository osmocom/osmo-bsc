#pragma once
#include "../../bscconfig.h"

#include <osmocom/sigtran/osmo_ss7.h>

#ifndef SIGTRAN_PRIVATE_STRUCTS

static inline struct osmo_ss7_as *osmo_ss7_route_get_dest_as(struct osmo_ss7_route *rt)
{
	return rt->dest.as;
}

static inline uint32_t osmo_ss7_instance_get_id(const struct osmo_ss7_instance *inst)
{
	return inst->cfg.id;
}

static inline struct osmo_ss7_instance *osmo_ss7_instances_llist_entry(struct llist_head *list)
{
	struct osmo_ss7_instance *pos;
	pos = llist_entry(list, struct osmo_ss7_instance, list);
	return pos;
}

static inline enum osmo_ss7_asp_protocol osmo_ss7_as_get_asp_protocol(const struct osmo_ss7_as *as)
{
	return as->cfg.proto;
}

struct osmo_ss7_asp *osmo_ss7_as_select_asp(struct osmo_ss7_as *as);

#endif
