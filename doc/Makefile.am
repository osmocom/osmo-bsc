SUBDIRS = \
	examples \
	$(NULL)

msc: \
	$(builddir)/handover.png \
	$(builddir)/assignment.png \
	$(builddir)/lchan-release.png \
	$(NULL)

$(builddir)/%.png: $(srcdir)/%.msc
	mscgen -T png -o $@ $<

.PHONY: poll
poll:
	while true; do $(MAKE) msc; sleep 1; done
