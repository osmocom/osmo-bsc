SUBDIRS = \
	examples \
	manuals \
	$(NULL)

msc: \
	$(builddir)/legend_for_ladder_diagrams.png \
	$(builddir)/handover.png \
	$(builddir)/assignment.png \
	$(builddir)/timeslot.png \
	$(builddir)/lchan.png \
	$(builddir)/ts-and-lchan-fsm-lifecycle.png \
	$(builddir)/handover-inter-bsc-out.png \
	$(builddir)/handover-inter-bsc-in.png \
	$(builddir)/mgw-endpoint.png \
	$(builddir)/location_services_ta.png \
	$(builddir)/codec_resolution.png \
	$(NULL)

dot: \
	$(builddir)/legend_for_fsm_diagrams.png \
	$(builddir)/assignment-fsm.png \
	$(builddir)/timeslot-fsm.png \
	$(builddir)/lchan-fsm.png \
	$(builddir)/lchan-rtp-fsm.png \
	$(builddir)/mgw-endpoint-fsm.png \
	$(builddir)/handover-intra-bsc-fsm.png \
	$(builddir)/handover-inter-bsc-out-fsm.png \
	$(builddir)/handover-inter-bsc-in-fsm.png \
	$(builddir)/mscpool-attach.png \
	$(builddir)/location_services_fsm_bsc.png \
	$(NULL)

$(builddir)/%.png: $(srcdir)/%.msc
	mscgen -T png -o $@ $<

$(builddir)/%.png: $(srcdir)/%.dot
	dot -Tpng $< > $@

.PHONY: poll
poll:
	while true; do $(MAKE) msc dot; sleep 1; done
