EXTRA_DIST = aoip-mgw-options.adoc \
    aoip-mgw-options-docinfo.xml \
    osmobsc-cbsp.adoc \
    osmobsc-cbsp-docinfo.xml \
    osmobsc-usermanual.adoc \
    osmobsc-usermanual-docinfo.xml \
    osmobsc-vty-reference.xml \
    osmux-reference.adoc \
    osmux-reference-docinfo.xml \
    cbsp \
    chapters \
    message-sequences \
    mgw \
    om2000 \
    regen_doc.sh \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmobsc-usermanual.adoc osmobsc-cbsp.adoc osmux-reference.adoc aoip-mgw-options.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc
  osmobsc-usermanual.pdf: $(srcdir)/chapters/*.adoc $(srcdir)/chapters/*.dot
  osmobsc-cbsp.pdf: $(srcdir)/cbsp/*.adoc #$(srcdir)/cbsp/*.dot $(srcdir)/abis/*.msc
  aoip-mgw-options.pdf: $(srcdir)/aoip-mgw-options.adoc $(srcdir)/mgw/*.msc

  VTY_REFERENCE = osmobsc-vty-reference.xml

  BUILT_REFERENCE_XML = $(builddir)/vty/bsc_vty_reference.xml
  $(builddir)/vty/bsc_vty_reference.xml: $(top_builddir)/src/osmo-bsc/osmo-bsc
	mkdir -p $(builddir)/vty
	$(top_builddir)/src/osmo-bsc/osmo-bsc --vty-ref-xml > $@

  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-bsc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
