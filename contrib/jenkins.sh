#!/usr/bin/env bash
# jenkins build helper script for osmo-bsc.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * WITH_MANUALS: build manual PDFs if set to "1"
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
# * IS_MASTER_BUILD: set to 1 when running from master-builds (not gerrit-verifications)
#

exit_tar_workspace() {
	if [ "$IS_MASTER_BUILD" = "1" ]; then
		tar -cJf "/tmp/workspace.tar.xz" "$base"
		mv /tmp/workspace.tar.xz "$base"
	fi

	cat-testlogs.sh
}

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi


set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

osmo-clean-workspace.sh

mkdir "$deps" || true

osmo-build-dep.sh libosmocore "" '--disable-doxygen --enable-gnutls'

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

# Check for wrong use of osmo_bts_has_feature (OS#5538)
bts_features_wrong_use="$(grep -r -n 'osmo_bts_has_feature.*->model->features' \
	| grep -v 'jenkins.sh' \
	| grep -v 'intentional check against bts model')" || true
if [ -n "$bts_features_wrong_use" ]; then
	set +x
	echo
	echo "ERROR: Don't use osmo_bts_has_feature with bts->model->features. Use bts->features instead."
	echo
	echo "$bts_features_wrong_use"
	exit 1
fi

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"
export PATH="$inst/bin:$PATH"

osmo-build-dep.sh libosmo-abis
osmo-build-dep.sh libosmo-netif
osmo-build-dep.sh libosmo-sccp
osmo-build-dep.sh osmo-mgw

# Additional configure options and depends
CONFIG=""
if [ "$WITH_MANUALS" = "1" ]; then
	CONFIG="--enable-manuals"
fi

set +x
echo
echo
echo
echo " =============================== osmo-bsc ==============================="
echo
set -x

cd "$base"
autoreconf --install --force
./configure --enable-sanitize --enable-external-tests --enable-werror $CONFIG
$MAKE $PARALLEL_MAKE
LD_LIBRARY_PATH="$inst/lib" $MAKE check \
  || exit_tar_workspace
LD_LIBRARY_PATH="$inst/lib" \
  DISTCHECK_CONFIGURE_FLAGS="--enable-external-tests --enable-werror $CONFIG" \
  $MAKE $PARALLEL_MAKE distcheck \
  || exit_tar_workspace

if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
	make -C "$base/doc/manuals" publish
fi

$MAKE $PARALLEL_MAKE maintainer-clean
osmo-clean-workspace.sh
