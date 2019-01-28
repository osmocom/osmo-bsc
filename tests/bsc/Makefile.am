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
	$(LIBOSMOLEGACYMGCP_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	bsc_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	bsc_test \
	$(NULL)

bsc_test_SOURCES = \
	bsc_test.c \
	$(NULL)

bsc_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/abis_nm.o \
	$(top_builddir)/src/osmo-bsc/arfcn_range_encode.o \
	$(top_builddir)/src/osmo-bsc/osmo_bsc_filter.o \
	$(top_builddir)/src/osmo-bsc/bsc_subscriber.o \
	$(top_builddir)/src/osmo-bsc/gsm_data.o \
	$(top_builddir)/src/osmo-bsc/handover_cfg.o \
	$(top_builddir)/src/osmo-bsc/handover_logic.o \
	$(top_builddir)/src/osmo-bsc/neighbor_ident.o \
	$(top_builddir)/src/osmo-bsc/net_init.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOLEGACYMGCP_LIBS) \
	$(LIBRARY_GSM) \
	-lrt \
	$(NULL)
