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

handover_test_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)
