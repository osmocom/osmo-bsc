AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOMGCP_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(NULL)

noinst_LIBRARIES = \
	libbsc.a \
	$(NULL)

libbsc_a_SOURCES = \
	abis_nm.c \
	abis_nm_vty.c \
	abis_om2000.c \
	abis_om2000_vty.c \
	abis_rsl.c \
	a_reset.c \
	acc_ramp.c \
	bsc_rll.c \
	bsc_subscriber.c \
	paging.c \
	bts_ericsson_rbs2000.c \
	bts_ipaccess_nanobts.c \
	bts_siemens_bs11.c \
	bts_nokia_site.c \
	bts_unknown.c \
	bts_sysmobts.c \
	chan_alloc.c \
	gsm_data.c \
	handover_decision.c \
	handover_logic.c \
	meas_rep.c \
	pcu_sock.c \
	rest_octets.c \
	system_information.c \
	e1_config.c \
	bsc_api.c \
	bsc_vty.c \
	gsm_04_08_utils.c \
	gsm_04_80_utils.c \
	bsc_init.c \
	bts_init.c \
	bsc_rf_ctrl.c \
	arfcn_range_encode.c \
	bsc_ctrl_commands.c \
	bsc_ctrl_lookup.c \
	net_init.c \
	bsc_dyn_ts.c \
	bts_ipaccess_nanobts_omlattr.c \
	handover_vty.c \
	handover_cfg.c \
	penalty_timers.c \
	handover_decision_2.c \
	bsc_subscr_conn_fsm.c \
	meas_feed.c \
	osmo_bsc_lcls.c \
	$(NULL)

