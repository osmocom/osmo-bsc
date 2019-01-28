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
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-bsc \
	$(NULL)

osmo_bsc_SOURCES = \
	a_reset.c \
	abis_nm.c \
	abis_nm_vty.c \
	abis_om2000.c \
	abis_om2000_vty.c \
	abis_rsl.c \
	acc_ramp.c \
	arfcn_range_encode.c \
	assignment_fsm.c \
	bsc_ctrl_commands.c \
	bsc_ctrl_lookup.c \
	bsc_init.c \
	bsc_rf_ctrl.c \
	bsc_rll.c \
	bsc_subscr_conn_fsm.c \
	bsc_subscriber.c \
	bsc_vty.c \
	bts_ericsson_rbs2000.c \
	bts_init.c \
	bts_ipaccess_nanobts.c \
	bts_ipaccess_nanobts_omlattr.c \
	bts_nokia_site.c \
	bts_siemens_bs11.c \
	bts_sysmobts.c \
	bts_unknown.c \
	chan_alloc.c \
	codec_pref.c \
	e1_config.c \
	gsm_04_08_rr.c \
	gsm_04_80_utils.c \
	gsm_data.c \
	handover_cfg.c \
	handover_decision.c \
	handover_decision_2.c \
	handover_fsm.c \
	handover_logic.c \
	handover_vty.c \
	lchan_fsm.c \
	lchan_rtp_fsm.c \
	lchan_select.c \
	meas_feed.c \
	meas_rep.c \
	mgw_endpoint_fsm.c \
	neighbor_ident.c \
	neighbor_ident_vty.c \
	net_init.c \
	gsm_08_08.c \
	osmo_bsc_bssap.c \
	osmo_bsc_ctrl.c \
	osmo_bsc_filter.c \
	osmo_bsc_grace.c \
	osmo_bsc_lcls.c \
	osmo_bsc_main.c \
	osmo_bsc_msc.c \
	osmo_bsc_sigtran.c \
	osmo_bsc_vty.c \
	paging.c \
	pcu_sock.c \
	penalty_timers.c \
	rest_octets.c \
	system_information.c \
	timeslot_fsm.c \
	$(NULL)

osmo_bsc_LDADD = \
	$(top_builddir)/src/libfilter/libfilter.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(NULL)
