AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(NULL)

AM_LDFLAGS = -no-install

check_PROGRAMS = \
	nanobts_omlattr_test \
	$(NULL)

EXTRA_DIST = \
	nanobts_omlattr_test.ok \
	$(NULL)

nanobts_omlattr_test_SOURCES = \
	nanobts_omlattr_test.c \
	$(NULL)

nanobts_omlattr_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/libbsc.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)
