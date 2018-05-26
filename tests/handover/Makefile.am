AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	handover_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	handover_test \
	$(NULL)

handover_test_SOURCES = \
	handover_test.c \
	$(NULL)

handover_test_LDFLAGS =\
	-Wl,--wrap=abis_rsl_sendmsg,--wrap=mgcp_conn_modify,--wrap=mgcp_conn_delete\
	$(NULL)

handover_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/a_reset.o \
	$(top_builddir)/src/osmo-bsc/abis_nm.o \
	$(top_builddir)/src/osmo-bsc/abis_rsl.o \
	$(top_builddir)/src/osmo-bsc/arfcn_range_encode.o \
	$(top_builddir)/src/osmo-bsc/bsc_api.o \
	$(top_builddir)/src/osmo-bsc/bsc_dyn_ts.o \
	$(top_builddir)/src/osmo-bsc/bsc_init.o \
	$(top_builddir)/src/osmo-bsc/bsc_rll.o \
	$(top_builddir)/src/osmo-bsc/bsc_subscr_conn_fsm.o \
	$(top_builddir)/src/osmo-bsc/bsc_subscriber.o \
	$(top_builddir)/src/osmo-bsc/bts_ipaccess_nanobts.o \
	$(top_builddir)/src/osmo-bsc/bts_ipaccess_nanobts_omlattr.o \
	$(top_builddir)/src/osmo-bsc/bts_sysmobts.o \
	$(top_builddir)/src/osmo-bsc/chan_alloc.o \
	$(top_builddir)/src/osmo-bsc/gsm_04_08_utils.o \
	$(top_builddir)/src/osmo-bsc/gsm_04_80_utils.o \
	$(top_builddir)/src/osmo-bsc/gsm_data.o \
	$(top_builddir)/src/osmo-bsc/handover_cfg.o \
	$(top_builddir)/src/osmo-bsc/handover_decision.o \
	$(top_builddir)/src/osmo-bsc/handover_decision_2.o \
	$(top_builddir)/src/osmo-bsc/handover_logic.o \
	$(top_builddir)/src/osmo-bsc/meas_rep.o \
	$(top_builddir)/src/osmo-bsc/osmo_bsc_lcls.o \
	$(top_builddir)/src/osmo-bsc/net_init.o \
	$(top_builddir)/src/osmo-bsc/paging.o \
	$(top_builddir)/src/osmo-bsc/pcu_sock.o \
	$(top_builddir)/src/osmo-bsc/penalty_timers.o \
	$(top_builddir)/src/osmo-bsc/rest_octets.o \
	$(top_builddir)/src/osmo-bsc/system_information.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(NULL)
