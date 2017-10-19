TOPDIR = ..

ASCIIDOC = osmobsc-usermanual.adoc osmux-reference.adoc aoip-mgw-options.adoc
include $(TOPDIR)/build/Makefile.asciidoc.inc
osmobsc-usermanual.pdf: chapters/*.adoc
aoip-mgw-options.pdf: aoip-mgw-options.adoc mgw/*.msc

VTY_REFERENCE = osmobsc-vty-reference.xml
include $(TOPDIR)/build/Makefile.vty-reference.inc

include $(TOPDIR)/build/Makefile.common.inc
