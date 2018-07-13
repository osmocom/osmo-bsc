AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(NULL)

EXTRA_DIST = \
	codec_pref_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	codec_pref_test \
	$(NULL)

codec_pref_test_SOURCES = \
	codec_pref_test.c \
	$(NULL)

codec_pref_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/codec_pref.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	-lrt \
	$(NULL)
