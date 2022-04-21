AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(NULL)

check_PROGRAMS = \
	gsm0408_test \
	$(NULL)

EXTRA_DIST = \
	gsm0408_test.ok \
	$(NULL)

gsm0408_test_SOURCES = \
	gsm0408_test.c \
	$(NULL)

gsm0408_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/libbsc.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)
