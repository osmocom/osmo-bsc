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
	$(COVERAGE_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	bssap_test.ok \
	bssap_test.err \
	$(NULL)

noinst_PROGRAMS = \
	bssap_test \
	$(NULL)

bssap_test_SOURCES = \
	bssap_test.c \
	$(top_srcdir)/src/osmo-bsc/osmo_bsc_bssap.c \
	$(top_srcdir)/src/osmo-bsc/osmo_bsc_sigtran.c \
	$(top_srcdir)/src/osmo-bsc/osmo_bsc_filter.c \
	$(top_srcdir)/src/osmo-bsc/osmo_bsc_grace.c \
	$(top_srcdir)/src/osmo-bsc/osmo_bsc_mgcp.c \
	$(NULL)

bssap_test_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(NULL)

bssap_test_LDFLAGS = \
	-Wl,--wrap=bsc_grace_paging_request \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/bssap_test >$(srcdir)/bssap_test.ok 2>$(srcdir)/bssap_test.err
