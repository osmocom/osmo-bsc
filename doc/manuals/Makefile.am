EXTRA_DIST = aoip-mgw-options.adoc \
    aoip-mgw-options-docinfo.xml \
    osmobsc-usermanual.adoc \
    osmobsc-usermanual-docinfo.xml \
    osmobsc-vty-reference.xml \
    osmux-reference.adoc \
    osmux-reference-docinfo.xml \
    chapters \
    message-sequences \
    mgw \
    om2000 \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmobsc-usermanual.adoc osmux-reference.adoc aoip-mgw-options.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc
  osmobsc-usermanual.pdf: $(srcdir)/chapters/*.adoc $(srcdir)/chapters/*.dot
  aoip-mgw-options.pdf: $(srcdir)/aoip-mgw-options.adoc $(srcdir)/mgw/*.msc

  VTY_REFERENCE = osmobsc-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
