AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

OSMO_LIBS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(NULL)

bin_PROGRAMS = \
	abisip-find \
	ipaccess-config \
	ipaccess-proxy \
	$(NULL)

abisip_find_LDADD = \
	$(OSMO_LIBS) \
	$(NULL)

abisip_find_SOURCES = \
	abisip-find.c \
	stubs.c \
	$(NULL)

ipaccess_config_SOURCES = \
	ipaccess-config.c \
	ipaccess-firmware.c \
	network_listen.c \
	stubs.c \
	$(NULL)

# FIXME: resolve the bogus dependencies patched around here:
ipaccess_config_LDADD = \
	$(top_builddir)/src/osmo-bsc/abis_nm.o \
	$(top_builddir)/src/osmo-bsc/bts_ipaccess_nanobts.o \
	$(top_builddir)/src/osmo-bsc/bts_ipaccess_nanobts_omlattr.o \
	$(top_builddir)/src/osmo-bsc/gsm_data.o \
	$(top_builddir)/src/osmo-bsc/net_init.o \
	$(OSMO_LIBS) \
	$(NULL)

ipaccess_proxy_SOURCES = \
	ipaccess-proxy.c \
	stubs.c \
	$(top_srcdir)/src/osmo-bsc/gsm_data.c \
	$(NULL)

ipaccess_proxy_LDADD = \
	$(OSMO_LIBS) \
	$(NULL)
