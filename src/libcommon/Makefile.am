AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMOLEGACYMGCP_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

noinst_LIBRARIES = \
	libcommon.a \
	$(NULL)

libcommon_a_SOURCES = \
	gsm_data.c \
	gsm_data_shared.c \
	talloc_ctx.c \
	handover_cfg.c \
	$(NULL)
