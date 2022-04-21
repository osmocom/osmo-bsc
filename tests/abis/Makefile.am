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
	abis_test.ok \
	$(NULL)

check_PROGRAMS = \
	abis_test \
	$(NULL)

abis_test_SOURCES = \
	abis_test.c \
	$(NULL)

abis_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/libbsc.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)
