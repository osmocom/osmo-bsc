AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)

noinst_PROGRAMS = \
	gsm0408_test \
	$(NULL)

EXTRA_DIST = \
	gsm0408_test.ok \
	$(NULL)

gsm0408_test_SOURCES = \
	gsm0408_test.c \
	$(NULL)

gsm0408_test_LDADD = \
	$(top_builddir)/src/osmo-bsc/abis_nm.o \
	$(top_builddir)/src/osmo-bsc/acc.o \
	$(top_builddir)/src/osmo-bsc/gsm_04_08_rr.o \
	$(top_builddir)/src/osmo-bsc/arfcn_range_encode.o \
	$(top_builddir)/src/osmo-bsc/bts.o \
	$(top_builddir)/src/osmo-bsc/bts_ipaccess_nanobts_omlattr.o \
	$(top_builddir)/src/osmo-bsc/bts_trx.o \
	$(top_builddir)/src/osmo-bsc/gsm_data.o \
	$(top_builddir)/src/osmo-bsc/net_init.o \
	$(top_builddir)/src/osmo-bsc/rest_octets.o \
	$(top_builddir)/src/osmo-bsc/system_information.o \
	$(top_builddir)/src/osmo-bsc/neighbor_ident.o \
	$(top_builddir)/src/osmo-bsc/nm_common_fsm.o \
	$(top_builddir)/src/osmo-bsc/nm_bts_sm_fsm.o \
	$(top_builddir)/src/osmo-bsc/nm_bts_fsm.o \
	$(top_builddir)/src/osmo-bsc/nm_bb_transc_fsm.o \
	$(top_builddir)/src/osmo-bsc/nm_channel_fsm.o \
	$(top_builddir)/src/osmo-bsc/nm_rcarrier_fsm.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)
