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
	acc_test.ok \
	$(NULL)

check_PROGRAMS = \
	acc_test \
	$(NULL)

acc_test_SOURCES = \
	acc_test.c \
	$(NULL)

acc_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/libbsc.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)
