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
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(SQLITE3_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

noinst_HEADERS = \
	meas_db.h \
	$(NULL)

bin_PROGRAMS = \
	bs11_config \
	isdnsync \
	meas_json \
	$(NULL)
if BUILD_MEAS_UDP2DB
bin_PROGRAMS += \
	osmo-meas-udp2db \
	$(NULL)
endif
if BUILD_MEAS_PCAP2DB
bin_PROGRAMS += \
	osmo-meas-pcap2db \
	$(NULL)
endif
if BUILD_MEAS_VIS
bin_PROGRAMS += \
	meas_vis \
	$(NULL)
endif

bs11_config_SOURCES = \
	bs11_config.c \
	$(NULL)

bs11_config_LDADD = \
	$(top_builddir)/src/osmo-bsc/libbsc.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)

isdnsync_SOURCES = \
	isdnsync.c \
	$(NULL)

meas_vis_SOURCES = \
	meas_vis.c \
	$(NULL)

meas_vis_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	-lcdk \
	-lncurses \
	$(NULL)

meas_vis_CFLAGS = \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(NULL)

osmo_meas_pcap2db_SOURCES = \
	meas_pcap2db.c \
	meas_db.c \
	$(NULL)

osmo_meas_pcap2db_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(SQLITE3_LIBS) \
	-lpcap \
	$(NULL)

osmo_meas_pcap2db_CFLAGS = \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)

osmo_meas_udp2db_SOURCES = \
	meas_udp2db.c \
	meas_db.c \
	$(NULL)

osmo_meas_udp2db_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(SQLITE3_LIBS) \
	$(NULL)

osmo_meas_udp2db_CFLAGS = \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)

meas_json_SOURCES = \
	meas_json.c \
	$(NULL)

meas_json_LDADD = \
	$(top_builddir)/src/osmo-bsc/libbsc.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)

meas_json_CFLAGS = \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)
