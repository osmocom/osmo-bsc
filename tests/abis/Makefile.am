AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	abis_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	abis_test \
	$(NULL)

abis_test_SOURCES = \
	abis_test.c \
	$(NULL)

abis_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/abis_nm.o \
	$(top_builddir)/src/osmo-bsc/gsm_data.o \
	$(top_builddir)/src/osmo-bsc/net_init.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)
