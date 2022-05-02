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
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	paging_test.ok \
	$(NULL)

check_PROGRAMS = \
	paging_test \
	$(NULL)

paging_test_SOURCES = \
	paging_test.c \
	$(NULL)

paging_test_LDFLAGS = \
	-Wl,--wrap=abis_rsl_sendmsg \
	$(NULL)

paging_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/libbsc.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)
