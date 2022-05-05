SUBDIRS = \
	abis \
	acc \
	bsc \
	codec_pref \
	gsm0408 \
	handover \
	nanobts_omlattr \
	paging \
	subscr \
	$(NULL)

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = \
	testsuite.at \
	$(srcdir)/package.m4 \
	$(TESTSUITE) \
	vty_test_runner.py \
	ctrl_test_runner.py \
	cbc.vty \
	gprs_bvci_default.vty \
	handover_cfg.vty \
	neighbor_ident.vty \
	nri_cfg.vty \
	osmo-bsc.vty \
	timer.vty \
	power_ctrl.vty \
	interf_meas.vty \
	acch_overpower.vty \
	ctrl/osmo-bsc-neigh-test.cfg \
	ctrl/osmo-bsc-apply-config-file.cfg \
	ctrl/osmo-bsc-apply-config-file-invalid.cfg \
	$(NULL)

TESTSUITE = $(srcdir)/testsuite

DISTCLEANFILES = \
	atconfig \
	$(NULL)

if ENABLE_EXT_TESTS
python-tests: $(BUILT_SOURCES)
	$(MAKE) vty-test
	osmotestvty.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	osmotestconfig.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	$(srcdir)/vty_test_runner.py -w $(abs_top_builddir) -v
	$(srcdir)/ctrl_test_runner.py -w $(abs_top_builddir) -v
else
python-tests: $(BUILT_SOURCES)
	echo "Not running python-based tests (determined at configure-time)"
endif

# Run a specific test with: 'make vty-test VTY_TEST=osmo-bsc.vty'
VTY_TEST ?= *.vty

# To update the VTY script from current application behavior,
# pass -u to vty_script_runner.py by doing:
#   make vty-test U=-u
vty-test:
	osmo_verify_transcript_vty.py -v \
		-n OsmoBSC -p 4242 \
		-r "$(top_builddir)/src/osmo-bsc/osmo-bsc -c $(top_srcdir)/doc/examples/osmo-bsc/osmo-bsc-minimal.cfg" \
		$(U) $(srcdir)/$(VTY_TEST)

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)
	$(MAKE) $(AM_MAKEFLAGS) python-tests

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
