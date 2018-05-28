SUBDIRS = \
	examples \
	$(NULL)

msc: \
	$(builddir)/handover.png \
	$(builddir)/assignment.png \
	$(builddir)/lchan-release.png \
	$(builddir)/ms-channel-request.png \
	$(builddir)/timeslot.png \
	$(builddir)/lchan.png \
	$(builddir)/ts-and-lchan-fsm-lifecycle.png \
	$(builddir)/handover-inter-bsc-mo.png \
	$(builddir)/handover-inter-bsc-mt.png \
	$(NULL)

dot: \
	$(builddir)/timeslot-fsm.png \
	$(builddir)/lchan-fsm.png \
	$(NULL)

$(builddir)/%.png: $(srcdir)/%.msc
	mscgen -T png -o $@ $<

$(builddir)/%.png: $(srcdir)/%.dot
	dot -Tpng $< > $@

.PHONY: poll
poll:
	while true; do $(MAKE) msc dot; sleep 1; done
