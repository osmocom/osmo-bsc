#!/usr/bin/env python3

# (C) 2013 by Jacob Erlbeck <jerlbeck@sysmocom.de>
# (C) 2014 by Holger Hans Peter Freyther
# based on vty_test_runner.py:
# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
# based on bsc_control.py.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import time
import unittest
import socket
import sys
import struct

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil
from osmopy.osmo_ipa import Ctrl, IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')
verbose = False

class TestCtrlBase(unittest.TestCase):

    def ctrl_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def ctrl_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_ctrl_cmd = self.ctrl_command()[:]
        config_index = osmo_ctrl_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_ctrl_cmd[cfi] = os.path.join(confpath, osmo_ctrl_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_ctrl_cmd)
        except OSError:
            print("Current directory: %s" % os.getcwd(), file=sys.stderr)
            print("Consider setting -b", file=sys.stderr)

        appstring = self.ctrl_app()[2]
        appport = self.ctrl_app()[0]
        self.connect("127.0.0.1", appport)
        self.next_id = 1000

    def tearDown(self):
        self.disconnect()
        osmoutil.end_proc(self.proc)

    def disconnect(self):
        if not (self.sock is None):
            self.sock.close()

    def connect(self, host, port):
        if verbose:
            print("Connecting to host %s:%i" % (host, port))

        retries = 30
        while True:
            try:
                sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sck.setblocking(1)
                sck.connect((host, port))
            except IOError:
                retries -= 1
                if retries <= 0:
                    raise
                time.sleep(.1)
                continue
            break
        self.sock = sck
        return sck

    def send(self, data):
        if verbose:
            print("Sending \"%s\"" %(data))
        data = Ctrl().add_header(data)
        return self.sock.send(data) == len(data)

    def send_set(self, var, value, id):
        setmsg = "SET %s %s %s" %(id, var, value)
        return self.send(setmsg)

    def send_get(self, var, id):
        getmsg = "GET %s %s" %(id, var)
        return self.send(getmsg)

    def do_set(self, var, value):
        id = self.next_id
        self.next_id += 1
        self.send_set(var, value, id)
        return self.recv_msgs()[id]

    def do_get(self, var):
        id = self.next_id
        self.next_id += 1
        self.send_get(var, id)
        return self.recv_msgs()[id]

    def recv_msgs(self):
        responses = {}
        data = self.sock.recv(4096)
        while (len(data)>0):
            (head, data) = IPA().split_combined(data)
            answer = Ctrl().rem_header(head).decode()
            if verbose:
                print("Got message:", answer)
            (mtype, id, msg) = answer.split(None, 2)
            id = int(id)
            rsp = {'mtype': mtype, 'id': id}
            if mtype == "ERROR":
                rsp['error'] = msg
            else:
                split = msg.split(None, 1)
                rsp['var'] = split[0]
                if len(split) > 1:
                    rsp['value'] = split[1]
                else:
                    rsp['value'] = None
            responses[id] = rsp

        if verbose:
            print("Decoded replies: ", responses)

        return responses


class TestCtrlBSC(TestCtrlBase):

    def tearDown(self):
        TestCtrlBase.tearDown(self)
        os.unlink("tmp_dummy_sock")

    def ctrl_command(self):
        return ["./src/osmo-bsc/osmo-bsc", "-r", "tmp_dummy_sock", "-c",
                "doc/examples/osmo-bsc/osmo-bsc.cfg"]

    def ctrl_app(self):
        return (4249, "./src/osmo-bsc/osmo-bsc", "OsmoBSC", "bsc")

    def testCtrlErrs(self):
        r = self.do_get('invalid')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Command not found')

        r = self.do_set('rf_locked', '999')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Value failed verification.')

        r = self.do_get('bts')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Error while parsing the index.')

        r = self.do_get('bts.999')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Error while resolving object')

    def testBtsLac(self):
        r = self.do_get('bts.0.location-area-code')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.location-area-code')
        self.assertEqual(r['value'], '1')

        r = self.do_set('bts.0.location-area-code', '23')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.location-area-code')
        self.assertEqual(r['value'], '23')

        r = self.do_get('bts.0.location-area-code')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.location-area-code')
        self.assertEqual(r['value'], '23')

        r = self.do_set('bts.0.location-area-code', '-1')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Input not within the range')

    def testBtsCi(self):
        r = self.do_get('bts.0.cell-identity')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.cell-identity')
        self.assertEqual(r['value'], '6969')

        r = self.do_set('bts.0.cell-identity', '23')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.cell-identity')
        self.assertEqual(r['value'], '23')

        r = self.do_get('bts.0.cell-identity')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.cell-identity')
        self.assertEqual(r['value'], '23')

        r = self.do_set('bts.0.cell-identity', '-1')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Input not within the range')

    def testBtsGenerateSystemInformation(self):
        r = self.do_get('bts.0.send-new-system-informations')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Write Only attribute')

        # No RSL links so it will fail
        r = self.do_set('bts.0.send-new-system-informations', '1')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Failed to generate SI')

    def testBtsChannelLoad(self):
        r = self.do_set('bts.0.channel-load', '1')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Read Only attribute')

        # No RSL link so everything is 0
        r = self.do_get('bts.0.channel-load')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['value'],
		'CCCH+SDCCH4,0,0 TCH/F,0,0 TCH/H,0,0 SDCCH8,0,0'
		+ ' DYNAMIC/IPACCESS,0,0 CCCH+SDCCH4+CBCH,0,0'
		+ ' SDCCH8+CBCH,0,0 DYNAMIC/OSMOCOM,0,0')

    def testBtsOmlConnectionState(self):
        """Check OML state. It will not be connected"""
        r = self.do_set('bts.0.oml-connection-state', '1')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Read Only attribute')

        # No RSL link so everything is 0
        r = self.do_get('bts.0.oml-connection-state')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['value'], 'disconnected')

    def testTrxPowerRed(self):
        r = self.do_get('bts.0.trx.0.max-power-reduction')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.trx.0.max-power-reduction')
        self.assertEqual(r['value'], '20')

        r = self.do_set('bts.0.trx.0.max-power-reduction', '22')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.trx.0.max-power-reduction')
        self.assertEqual(r['value'], '22')

        r = self.do_get('bts.0.trx.0.max-power-reduction')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.trx.0.max-power-reduction')
        self.assertEqual(r['value'], '22')

        r = self.do_set('bts.0.trx.0.max-power-reduction', '1')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Value must be even')

    def testTrxArfcn(self):
        r = self.do_get('bts.0.trx.0.arfcn')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.trx.0.arfcn')
        self.assertEqual(r['value'], '871')

        r = self.do_set('bts.0.trx.0.arfcn', '873')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.trx.0.arfcn')
        self.assertEqual(r['value'], '873')

        r = self.do_get('bts.0.trx.0.arfcn')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.trx.0.arfcn')
        self.assertEqual(r['value'], '873')

        r = self.do_set('bts.0.trx.0.arfcn', '2000')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Input not within the range')

    def testRfLock(self):
        r = self.do_get('bts.0.rf_state')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.rf_state')
        self.assertEqual(r['value'], 'inoperational,locked,on')

        r = self.do_set('rf_locked', '1')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'rf_locked')
        self.assertEqual(r['value'], '1')

        time.sleep(1.5)

        r = self.do_get('bts.0.rf_state')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.rf_state')
        self.assertEqual(r['value'], 'inoperational,locked,off')

        r = self.do_get('rf_locked')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'rf_locked')
        self.assertEqual(r['value'], 'state=off,policy=off')

        r = self.do_set('rf_locked', '0')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'rf_locked')
        self.assertEqual(r['value'], '0')

        time.sleep(1.5)

        r = self.do_get('bts.0.rf_state')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.rf_state')
        self.assertEqual(r['value'], 'inoperational,locked,on')

        r = self.do_get('rf_locked')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'rf_locked')
        self.assertEqual(r['value'], 'state=off,policy=on')

    def testTimezone(self):
        r = self.do_get('timezone')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'timezone')
        self.assertEqual(r['value'], 'off')

        r = self.do_set('timezone', '-2,15,2')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'timezone')
        self.assertEqual(r['value'], '-2,15,2')

        r = self.do_get('timezone')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'timezone')
        self.assertEqual(r['value'], '-2,15,2')

        # Test invalid input
        r = self.do_set('timezone', '-2,15,2,5,6,7')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'timezone')
        self.assertEqual(r['value'], '-2,15,2')

        r = self.do_set('timezone', '-2,15')
        self.assertEqual(r['mtype'], 'ERROR')
        r = self.do_set('timezone', '-2')
        self.assertEqual(r['mtype'], 'ERROR')
        r = self.do_set('timezone', '1')

        r = self.do_set('timezone', 'off')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'timezone')
        self.assertEqual(r['value'], 'off')

        r = self.do_get('timezone')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'timezone')
        self.assertEqual(r['value'], 'off')

    def testMcc(self):
        r = self.do_set('mcc', '23')
        r = self.do_get('mcc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mcc')
        self.assertEqual(r['value'], '023')

        r = self.do_set('mcc', '023')
        r = self.do_get('mcc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mcc')
        self.assertEqual(r['value'], '023')

    def testMnc(self):
        r = self.do_set('mnc', '9')
        r = self.do_get('mnc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mnc')
        self.assertEqual(r['value'], '09')

        r = self.do_set('mnc', '09')
        r = self.do_get('mnc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mnc')
        self.assertEqual(r['value'], '09')

        r = self.do_set('mnc', '009')
        r = self.do_get('mnc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mnc')
        self.assertEqual(r['value'], '009')


    def testMccMncApply(self):
        # Test some invalid input
        r = self.do_set('mcc-mnc-apply', 'WRONG')
        self.assertEqual(r['mtype'], 'ERROR')

        r = self.do_set('mcc-mnc-apply', '1,')
        self.assertEqual(r['mtype'], 'ERROR')

        r = self.do_set('mcc-mnc-apply', '200,3')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'mcc-mnc-apply')
        self.assertEqual(r['value'], 'Tried to drop the BTS')

        # Set it again
        r = self.do_set('mcc-mnc-apply', '200,3')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'mcc-mnc-apply')
        self.assertEqual(r['value'], 'Nothing changed')

        # Change it
        r = self.do_set('mcc-mnc-apply', '200,4')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'mcc-mnc-apply')
        self.assertEqual(r['value'], 'Tried to drop the BTS')

        # Change it
        r = self.do_set('mcc-mnc-apply', '201,4')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'mcc-mnc-apply')
        self.assertEqual(r['value'], 'Tried to drop the BTS')

        # Verify
        r = self.do_get('mnc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mnc')
        self.assertEqual(r['value'], '04')

        r = self.do_get('mcc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mcc')
        self.assertEqual(r['value'], '201')

        # Change it
        r = self.do_set('mcc-mnc-apply', '202,03')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'mcc-mnc-apply')
        self.assertEqual(r['value'], 'Tried to drop the BTS')

        r = self.do_get('mnc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mnc')
        self.assertEqual(r['value'], '03')

        r = self.do_get('mcc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mcc')
        self.assertEqual(r['value'], '202')

        # Test MNC with 3 digits
        r = self.do_set('mcc-mnc-apply', '2,003')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'mcc-mnc-apply')
        self.assertEqual(r['value'], 'Tried to drop the BTS')

        r = self.do_get('mnc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mnc')
        self.assertEqual(r['value'], '003')

        r = self.do_get('mcc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mcc')
        self.assertEqual(r['value'], '002')

        # Set same MNC with 3 digits
        r = self.do_set('mcc-mnc-apply', '2,003')
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'mcc-mnc-apply')
        self.assertEqual(r['value'], 'Nothing changed')

        r = self.do_get('mnc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mnc')
        self.assertEqual(r['value'], '003')

        r = self.do_get('mcc')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'mcc')
        self.assertEqual(r['value'], '002')


    def testApplyConfigFile(self):

        vty_file = os.path.join(confpath, 'tests/ctrl/osmo-bsc-apply-config-file.cfg')
        vty_file_invalid = os.path.join(confpath, 'tests/ctrl/osmo-bsc-apply-config-file-invalid.cfg')

        # Test some invalid input
        r = self.do_set('apply-config-file', 'wrong-file-name-nonexistent')
        self.assertEqual(r['mtype'], 'ERROR')

        # Test some existing file with invalid content
        r = self.do_set('apply-config-file', vty_file_invalid)
        self.assertEqual(r['mtype'], 'ERROR')

        #bts1 shouldn't exist yet, let's check:
        r = self.do_get('bts.1.location-area-code')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Error while resolving object')

        r = self.do_set('apply-config-file', vty_file)
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'apply-config-file')
        self.assertEqual(r['value'], 'OK')

        # BTS1 should exist now:
        r = self.do_get('bts.1.location-area-code')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.1.location-area-code')
        self.assertEqual(r['value'], '1')

        # Set it again
        r = self.do_set('apply-config-file', vty_file)
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'apply-config-file')
        self.assertEqual(r['value'], 'OK')

    def testNeighborList(self):
	# Enter manual neighbor-list mode
        r = self.do_set('bts.0.neighbor-list.mode', 'manual')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-list.mode')
        self.assertEqual(r['value'], 'OK')

	# Add an ARFCN
        r = self.do_set('bts.0.neighbor-list.add', '123')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-list.add')
        self.assertEqual(r['value'], 'OK')

	# Delete the ARFCN again
        r = self.do_set('bts.0.neighbor-list.del', '123')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-list.del')
        self.assertEqual(r['value'], 'OK')

	# Go back to automatic neighbor-list mode
        r = self.do_set('bts.0.neighbor-list.mode', 'automatic')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-list.mode')
        self.assertEqual(r['value'], 'OK')

	# This must not work as we are in automatic neighbor-list mode
        r = self.do_set('bts.0.neighbor-list.add', '123')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Neighbor list not in manual mode')

	# Try an invalid neighbor-list mode
        r = self.do_set('bts.0.neighbor-list.mode', 'qwertzuiop')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Invalid mode')

class TestCtrlBSCNeighbor(TestCtrlBase):

    def tearDown(self):
        TestCtrlBase.tearDown(self)
        os.unlink("tmp_dummy_sock")

    def ctrl_command(self):
        return ["./src/osmo-bsc/osmo-bsc", "-r", "tmp_dummy_sock", "-c",
                "tests/ctrl/osmo-bsc-neigh-test.cfg"]

    def ctrl_app(self):
        return (4248, "./src/osmo-bsc/osmo-bsc", "OsmoBSC", "bsc")

    def testCtrlNeighborResolutionLocalBtsNr(self):
        r = self.do_get('neighbor_resolve_cgi_ps_from_lac_ci.1.123.871.63')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'neighbor_resolve_cgi_ps_from_lac_ci.1.123.871.63')
        self.assertEqual(r['value'], '001-01-1-5-6969')

    def testCtrlNeighborResolutionLocalWithoutArfcnBsic(self):
        r = self.do_get('neighbor_resolve_cgi_ps_from_lac_ci.1.6969.880.55')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'neighbor_resolve_cgi_ps_from_lac_ci.1.6969.880.55')
        self.assertEqual(r['value'], '001-01-1-6-123')

    def testCtrlNeighborResolutionWrongSyntax(self):
        r = self.do_get('neighbor_resolve_cgi_ps_from_lac_ci')
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'The format is <src_lac>,<src_cell_id>,<dst_arfcn>,<dst_bsic>')

    def testCtrlNeighborResolutionRemote(self):
        r = self.do_get('neighbor_resolve_cgi_ps_from_lac_ci.1.6969.23.32')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'neighbor_resolve_cgi_ps_from_lac_ci.1.6969.23.32')
        self.assertEqual(r['value'], '023-42-423-2-5')


class TestCtrlBSCNeighborCell(TestCtrlBase):

    def tearDown(self):
        TestCtrlBase.tearDown(self)
        os.unlink("tmp_dummy_sock")

    def ctrl_command(self):
        return ["./src/osmo-bsc/osmo-bsc", "-r", "tmp_dummy_sock", "-c",
                "tests/ctrl/osmo-bsc-neigh-test.cfg"]

    def ctrl_app(self):
        return (4249, "./src/osmo-bsc/osmo-bsc", "OsmoBSC", "bsc")

    def testCtrlListBTS(self):
    # Get BTS local neighbors (configured via 'neighbor cgi-ps ...')
        r = self.do_get('bts.0.neighbor-bts.list')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-bts.list')
        self.assertEqual(r['value'], '1')

    # Get BTS locally configured neighbors (when none configured)
        r = self.do_get('bts.2.neighbor-bts.list')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.2.neighbor-bts.list')
        self.assertEqual(r['value'], None)

    # Get BTS locally configured neighbors
        r = self.do_get('bts.1.neighbor-bts.list')
        self.assertEqual(r['mtype'], 'GET_REPLY')
        self.assertEqual(r['var'], 'bts.1.neighbor-bts.list')
        self.assertEqual(r['value'], '0,2')

    def testCtrlAddDelBTS(self):
        r = self.do_set('bts.0.neighbor-bts.add', '1')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-bts.add')
        self.assertEqual(r['value'], 'OK')
        r = self.do_set('bts.0.neighbor-bts.del', '1')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-bts.del')
        self.assertEqual(r['value'], 'OK')

    def testCtrlAddDelLAC(self):
	# without ARFCN+BSIC:
        r = self.do_set('bts.0.neighbor-lac.add', '100')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-lac.add')
        self.assertEqual(r['value'], 'OK')
        r = self.do_set('bts.0.neighbor-lac.del', '100')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-lac.del')
        self.assertEqual(r['value'], 'OK')

	# with ARFCN+BSIC:
        r = self.do_set('bts.0.neighbor-lac.add', '100-123-4')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-lac.add')
        self.assertEqual(r['value'], 'OK')
        r = self.do_set('bts.0.neighbor-lac.del', '100-123-4')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-lac.del')
        self.assertEqual(r['value'], 'OK')

    def testCtrlAddDelLACCI(self):
	# without ARFCN+BSIC:
        r = self.do_set('bts.0.neighbor-lac-ci.add', '100-200')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-lac-ci.add')
        self.assertEqual(r['value'], 'OK')
        r = self.do_set('bts.0.neighbor-lac-ci.del', '100-200')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-lac-ci.del')
        self.assertEqual(r['value'], 'OK')

	# with ARFCN+BSIC:
        r = self.do_set('bts.0.neighbor-lac-ci.add', '100-200-123-any')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-lac-ci.add')
        self.assertEqual(r['value'], 'OK')
        r = self.do_set('bts.0.neighbor-lac-ci.del', '100-200-123-any')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-lac-ci.del')
        self.assertEqual(r['value'], 'OK')

    def testCtrlAddDelCGI(self):
	# without ARFCN+BSIC:
        r = self.do_set('bts.0.neighbor-cgi.add', '001-01-100-200')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-cgi.add')
        self.assertEqual(r['value'], 'OK')
        r = self.do_set('bts.0.neighbor-cgi.del', '001-01-100-200')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-cgi.del')
        self.assertEqual(r['value'], 'OK')

	# with ARFCN+BSIC:
        r = self.do_set('bts.0.neighbor-cgi.add', '001-01-100-200-123-4')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-cgi.add')
        self.assertEqual(r['value'], 'OK')
        r = self.do_set('bts.0.neighbor-cgi.del', '001-01-100-200-123-4')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-cgi.del')
        self.assertEqual(r['value'], 'OK')

    def testCtrlAddDelCGIPS(self):
	# without ARFCN+BSIC:
        r = self.do_set('bts.0.neighbor-cgi-ps.add', '001-01-100-33-200')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-cgi-ps.add')
        self.assertEqual(r['value'], 'OK')
        r = self.do_set('bts.0.neighbor-cgi-ps.del', '001-01-100-33-200')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-cgi-ps.del')
        self.assertEqual(r['value'], 'OK')

	# with ARFCN+BSIC:
        r = self.do_set('bts.0.neighbor-cgi-ps.add', '001-01-100-33-200-123-any')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-cgi-ps.add')
        self.assertEqual(r['value'], 'OK')
        r = self.do_set('bts.0.neighbor-cgi-ps.del', '001-01-100-33-200-123-any')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-cgi-ps.del')
        self.assertEqual(r['value'], 'OK')

    def testCtrlClearNeighbors(self):
        r = self.do_set('bts.0.neighbor-clear', 'ignored')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'SET_REPLY')
        self.assertEqual(r['var'], 'bts.0.neighbor-clear')
        self.assertEqual(r['value'], 'OK')

    def testCtrlErrs(self):
	# Missing BSIC
        r = self.do_set('bts.0.neighbor-lac.add', '100-123')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Value failed verification.')

	# Short value (missing RAC)
        r = self.do_set('bts.0.neighbor-cgi-ps.del', '001-01-100-200-123-1')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Value failed verification.')

	# Long value
        r = self.do_set('bts.0.neighbor-cgi-ps.del', '001-01-100-33-200-123-1-2')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Value failed verification.')

	# Out of range values
        r = self.do_set('bts.0.neighbor-cgi.add', '100001-1123401-100-200')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Value failed verification.')

	# Garbage
        r = self.do_set('bts.0.neighbor-lac-ci.add', '0G1-Z1-1U0-a3-2p0')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Value failed verification.')

	# Delete something that shouldn't be there
        r = self.do_set('bts.0.neighbor-cgi-ps.del', '001-01-100-33-200-123-any')
        print('respose: ' + str(r))
        self.assertEqual(r['mtype'], 'ERROR')
        self.assertEqual(r['error'], 'Failed to delete neighbor')


def add_bsc_test(suite, workdir, klass):
    if not os.path.isfile(os.path.join(workdir, "src/osmo-bsc/osmo-bsc")):
        print("Skipping the BSC test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(klass)
    suite.addTest(test)

if __name__ == '__main__':
    import argparse
    import sys

    workdir = '.'

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="verbose mode")
    parser.add_argument("-p", "--pythonconfpath", dest="p",
                        help="searchpath for config")
    parser.add_argument("-w", "--workdir", dest="w",
                        help="Working directory")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2
        verbose = True

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print("confpath %s, workdir %s" % (confpath, workdir))
    os.chdir(workdir)
    print("Running tests for specific control commands")
    suite = unittest.TestSuite()
    add_bsc_test(suite, workdir, TestCtrlBSC)
    add_bsc_test(suite, workdir, TestCtrlBSCNeighbor)
    add_bsc_test(suite, workdir, TestCtrlBSCNeighborCell)
    res = unittest.TextTestRunner(verbosity=verbose_level).run(suite)
    sys.exit(len(res.errors) + len(res.failures))
