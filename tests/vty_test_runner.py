#!/usr/bin/env python2

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
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

import os, sys
import time
import unittest
import socket
import subprocess

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil

# add $top_srcdir/contrib to find ipa.py
sys.path.append(os.path.join(sys.path[0], '..', 'contrib'))

from ipa import IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')

class TestVTYBase(unittest.TestCase):

    def checkForEndAndExit(self):
        res = self.vty.command("list")
        #print ('looking for "exit"\n')
        self.assert_(res.find('  exit\r') > 0)
        #print 'found "exit"\nlooking for "end"\n'
        self.assert_(res.find('  end\r') > 0)
        #print 'found "end"\n'

    def vty_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def vty_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_vty_cmd = self.vty_command()[:]
        config_index = osmo_vty_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_vty_cmd[cfi] = os.path.join(confpath, osmo_vty_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_vty_cmd)
        except OSError:
            print >> sys.stderr, "Current directory: %s" % os.getcwd()
            print >> sys.stderr, "Consider setting -b"

        appstring = self.vty_app()[2]
        appport = self.vty_app()[0]
        self.vty = obscvty.VTYInteract(appstring, "127.0.0.1", appport)

    def tearDown(self):
        if self.vty:
            self.vty._close_socket()
        self.vty = None
        osmoutil.end_proc(self.proc)


class TestVTYGenericBSC(TestVTYBase):

    def _testConfigNetworkTree(self, include_bsc_items=True):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal",['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("network",['']))
        self.assertEquals(self.vty.node(), 'config-net')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("bts 0",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("trx 0",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts-trx')
        self.checkForEndAndExit()
        self.vty.command("write terminal")
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertTrue(self.vty.verify("bts 1",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("trx 1",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts-trx')
        self.checkForEndAndExit()
        self.vty.command("write terminal")
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEquals(self.vty.node(), 'config-net')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertTrue(self.vty.node() is None)


class TestVTYBSC(TestVTYGenericBSC):

    def vty_command(self):
        return ["./src/osmo-bsc/osmo-bsc", "-c",
                "doc/examples/osmo-bsc/osmo-bsc.cfg"]

    def vty_app(self):
        return (4242, "./src/osmo-bsc/osmo-bsc", "OsmoBSC", "bsc")

    def testConfigNetworkTree(self):
        self._testConfigNetworkTree()

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal", ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("msc 0", ['']))
        self.assertEquals(self.vty.node(), 'config-msc')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("bsc", ['']))
        self.assertEquals(self.vty.node(), 'config-bsc')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertTrue(self.vty.node() is None)

    def testUssdNotificationsMsc(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("msc")

        # Test invalid input
        self.vty.verify("bsc-msc-lost-text", ['% Command incomplete.'])
        self.vty.verify("bsc-welcome-text", ['% Command incomplete.'])
        self.vty.verify("bsc-grace-text", ['% Command incomplete.'])

        # Enable USSD notifications
        self.vty.verify("bsc-msc-lost-text MSC disconnected", [''])
        self.vty.verify("bsc-welcome-text Hello MS", [''])
        self.vty.verify("bsc-grace-text In grace period", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assert_(res.find('bsc-msc-lost-text MSC disconnected') > 0)
        self.assertEquals(res.find('no bsc-msc-lost-text'), -1)
        self.assert_(res.find('bsc-welcome-text Hello MS') > 0)
        self.assertEquals(res.find('no bsc-welcome-text'), -1)
        self.assert_(res.find('bsc-grace-text In grace period') > 0)
        self.assertEquals(res.find('no bsc-grace-text'), -1)

        # Now disable it..
        self.vty.verify("no bsc-msc-lost-text", [''])
        self.vty.verify("no bsc-welcome-text", [''])
        self.vty.verify("no bsc-grace-text", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEquals(res.find('bsc-msc-lost-text MSC disconnected'), -1)
        self.assert_(res.find('no bsc-msc-lost-text') > 0)
        self.assertEquals(res.find('bsc-welcome-text Hello MS'), -1)
        self.assert_(res.find('no bsc-welcome-text') > 0)
        self.assertEquals(res.find('bsc-grace-text In grace period'), -1)
        self.assert_(res.find('no bsc-grace-text') > 0)

    def testUssdNotificationsBsc(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("bsc")

        # Test invalid input
        self.vty.verify("missing-msc-text", ['% Command incomplete.'])

        # Enable USSD notifications
        self.vty.verify("missing-msc-text No MSC found", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assert_(res.find('missing-msc-text No MSC found') > 0)
        self.assertEquals(res.find('no missing-msc-text'), -1)

        # Now disable it..
        self.vty.verify("no missing-msc-text", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEquals(res.find('missing-msc-text No MSC found'), -1)
        self.assert_(res.find('no missing-msc-text') > 0)

    def testNetworkTimezone(self):
        self.vty.enable()
        self.vty.verify("configure terminal", [''])
        self.vty.verify("network", [''])

        # Test invalid input
        self.vty.verify("timezone", ['% Command incomplete.'])
        self.vty.verify("timezone 20 0", ['% Unknown command.'])
        self.vty.verify("timezone 0 11", ['% Unknown command.'])
        self.vty.verify("timezone 0 0 99", ['% Unknown command.'])

        # Set time zone without DST
        self.vty.verify("timezone 2 30", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assert_(res.find('timezone 2 30') > 0)
        self.assertEquals(res.find('timezone 2 30 '), -1)

        # Set time zone with DST
        self.vty.verify("timezone 2 30 1", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assert_(res.find('timezone 2 30 1') > 0)

        # Now disable it..
        self.vty.verify("no timezone", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEquals(res.find(' timezone'), -1)

    def testShowNetwork(self):
        res = self.vty.command("show network")
        self.assert_(res.startswith('BSC is on Country Code') >= 0)

    def testPingPongConfiguration(self):
        self.vty.enable()
        self.vty.verify("configure terminal", [''])
        self.vty.verify("msc 0", [''])

        self.vty.verify("timeout-ping 12", [''])
        self.vty.verify("timeout-pong 14", [''])
        res = self.vty.command("show running-config")
        self.assert_(res.find(" timeout-ping 12") > 0)
        self.assert_(res.find(" timeout-pong 14") > 0)
        self.assert_(res.find(" no timeout-ping advanced") > 0)

        self.vty.verify("timeout-ping advanced", [''])
        res = self.vty.command("show running-config")
        self.assert_(res.find(" timeout-ping 12") > 0)
        self.assert_(res.find(" timeout-pong 14") > 0)
        self.assert_(res.find(" timeout-ping advanced") > 0)

        self.vty.verify("no timeout-ping advanced", [''])
        res = self.vty.command("show running-config")
        self.assert_(res.find(" timeout-ping 12") > 0)
        self.assert_(res.find(" timeout-pong 14") > 0)
        self.assert_(res.find(" no timeout-ping advanced") > 0)

        self.vty.verify("no timeout-ping", [''])
        res = self.vty.command("show running-config")
        self.assertEquals(res.find(" timeout-ping 12"), -1)
        self.assertEquals(res.find(" timeout-pong 14"), -1)
        self.assertEquals(res.find(" no timeout-ping advanced"), -1)
        self.assert_(res.find(" no timeout-ping") > 0)

        self.vty.verify("timeout-ping advanced", ['%ping handling is disabled. Enable it first.'])

        # And back to enabling it
        self.vty.verify("timeout-ping 12", [''])
        self.vty.verify("timeout-pong 14", [''])
        res = self.vty.command("show running-config")
        self.assert_(res.find(" timeout-ping 12") > 0)
        self.assert_(res.find(" timeout-pong 14") > 0)
        self.assert_(res.find(" timeout-ping advanced") > 0)

    def testMscDataCoreLACCI(self):
        self.vty.enable()
        res = self.vty.command("show running-config")
        self.assertEquals(res.find("core-location-area-code"), -1)
        self.assertEquals(res.find("core-cell-identity"), -1)

        self.vty.command("configure terminal")
        self.vty.command("msc 0")
        self.vty.command("core-location-area-code 666")
        self.vty.command("core-cell-identity 333")

        res = self.vty.command("show running-config")
        self.assert_(res.find("core-location-area-code 666") > 0)
        self.assert_(res.find("core-cell-identity 333") > 0)

class TestVTYNAT(TestVTYGenericBSC):

    def vty_command(self):
        return ["./src/osmo-bsc_nat/osmo-bsc_nat", "-l", "127.0.0.1", "-c",
                "doc/examples/osmo-bsc_nat/osmo-bsc_nat.cfg"]

    def vty_app(self):
        return (4244, "src/osmo-bsc_nat/osmo-bsc_nat",  "OsmoBSCNAT", "nat")

    def testBSCreload(self):
        # Use different port for the mock msc to avoid clashing with
        # the osmo-bsc_nat itself
        ip = "127.0.0.1"
        port = 5522
        self.vty.enable()
        bscs1 = self.vty.command("show bscs-config")
        nat_bsc_reload(self)
        bscs2 = self.vty.command("show bscs-config")
        # check that multiple calls to bscs-config-file give the same result
        self.assertEquals(bscs1, bscs2)

        # add new bsc
        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.command("bsc 5")
        self.vty.command("token key")
        self.vty.command("location_area_code 666")
        self.vty.command("end")

        # update bsc token
        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.command("bsc 1")
        self.vty.command("token xyu")
        self.vty.command("end")

        nat_msc_ip(self, ip, port)
        msc_socket, msc = nat_msc_test(self, ip, port, verbose=True)
        try:
            b0 = nat_bsc_sock_test(0, "lol", verbose=True, proc=self.proc)
            b1 = nat_bsc_sock_test(1, "xyu", verbose=True, proc=self.proc)
            b2 = nat_bsc_sock_test(5, "key", verbose=True, proc=self.proc)

            self.assertEquals("3 BSCs configured", self.vty.command("show nat num-bscs-configured"))
            self.assertTrue(3 == nat_bsc_num_con(self))
            self.assertEquals("MSC is connected: 1", self.vty.command("show msc connection"))

            nat_bsc_reload(self)
            bscs2 = self.vty.command("show bscs-config")
            # check that the reset to initial config succeeded
            self.assertEquals(bscs1, bscs2)

            self.assertEquals("2 BSCs configured", self.vty.command("show nat num-bscs-configured"))
            self.assertTrue(1 == nat_bsc_num_con(self))
            rem = self.vty.command("show bsc connections").split(' ')
            # remaining connection is for BSC0
            self.assertEquals('0', rem[2])
            # remaining connection is authorized
            self.assertEquals('1', rem[4])
            self.assertEquals("MSC is connected: 1", self.vty.command("show msc connection"))
        finally:
            msc.close()
            msc_socket.close()

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('mgcp', ['']))
        self.assertEquals(self.vty.node(), 'config-mgcp')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('nat', ['']))
        self.assertEquals(self.vty.node(), 'config-nat')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('bsc 0', ['']))
        self.assertEquals(self.vty.node(), 'config-nat-bsc')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config-nat')
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertTrue(self.vty.node() is None)

    def testRewriteNoRewrite(self):
        self.vty.enable()
        res = self.vty.command("configure terminal")
        res = self.vty.command("nat")
        res = self.vty.command("number-rewrite rewrite.cfg")
        res = self.vty.command("no number-rewrite")

    def testEnsureNoEnsureModeSet(self):
        self.vty.enable()
        res = self.vty.command("configure terminal")
        res = self.vty.command("nat")

        # Ensure the default
        res = self.vty.command("show running-config")
        self.assert_(res.find('\n sdp-ensure-amr-mode-set') > 0)

        self.vty.command("sdp-ensure-amr-mode-set")
        res = self.vty.command("show running-config")
        self.assert_(res.find('\n sdp-ensure-amr-mode-set') > 0)

        self.vty.command("no sdp-ensure-amr-mode-set")
        res = self.vty.command("show running-config")
        self.assert_(res.find('\n no sdp-ensure-amr-mode-set') > 0)

    def testRewritePostNoRewrite(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.verify("number-rewrite-post rewrite.cfg", [''])
        self.vty.verify("no number-rewrite-post", [''])


    def testPrefixTreeLoading(self):
        cfg = os.path.join(confpath, "tests/bsc-nat-trie/prefixes.csv")

        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("nat")
        res = self.vty.command("prefix-tree %s" % cfg)
        self.assertEqual(res, "% prefix-tree loaded 17 rules.")
        self.vty.command("end")

        res = self.vty.command("show prefix-tree")
        self.assertEqual(res, '1,1\r\n12,2\r\n123,3\r\n1234,4\r\n12345,5\r\n123456,6\r\n1234567,7\r\n12345678,8\r\n123456789,9\r\n1234567890,10\r\n13,11\r\n14,12\r\n15,13\r\n16,14\r\n82,16\r\n823455,15\r\n+49123,17')

        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.command("no prefix-tree")
        self.vty.command("end")

        res = self.vty.command("show prefix-tree")
        self.assertEqual(res, "% there is now prefix tree loaded.")

    def testUssdSideChannelProvider(self):
        self.vty.command("end")
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.command("ussd-token key")
        self.vty.command("end")

        res = self.vty.verify("show ussd-connection", ['The USSD side channel provider is not connected and not authorized.'])
        self.assertTrue(res)

        ussdSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ussdSocket.connect(('127.0.0.1', 5001))
        ussdSocket.settimeout(2.0)
        print "Connected to %s:%d" % ussdSocket.getpeername()

        print "Expecting ID_GET request"
        data = ussdSocket.recv(4)
        self.assertEqual(data, "\x00\x01\xfe\x04")

        print "Going to send ID_RESP response"
        res = ussdSocket.send(IPA().id_resp(IPA().tag_name('key')))
        self.assertEqual(res, 10)

        # initiating PING/PONG cycle to know, that the ID_RESP message has been processed

        print "Going to send PING request"
        res = ussdSocket.send(IPA().ping())
        self.assertEqual(res, 4)

        print "Expecting PONG response"
        data = ussdSocket.recv(4)
        self.assertEqual(data, "\x00\x01\xfe\x01")

        res = self.vty.verify("show ussd-connection", ['The USSD side channel provider is connected and authorized.'])
        self.assertTrue(res)

        print "Going to shut down connection"
        ussdSocket.shutdown(socket.SHUT_WR)

        print "Expecting EOF"
        data = ussdSocket.recv(4)
        self.assertEqual(data, "")

        ussdSocket.close()

        res = self.vty.verify("show ussd-connection", ['The USSD side channel provider is not connected and not authorized.'])
        self.assertTrue(res)

    def testAccessList(self):
        """
        Verify that the imsi-deny can have a reject cause or no reject cause
        """
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("nat")

        # Old default
        self.vty.command("access-list test-default imsi-deny ^123[0-9]*$")
        res = self.vty.command("show running-config").split("\r\n")
        asserted = False
        for line in res:
           if line.startswith(" access-list test-default"):
                self.assertEqual(line, " access-list test-default imsi-deny ^123[0-9]*$ 11 11")
                asserted = True
        self.assert_(asserted)

        # Check the optional CM Service Reject Cause
        self.vty.command("access-list test-cm-deny imsi-deny ^123[0-9]*$ 42").split("\r\n")
        res = self.vty.command("show running-config").split("\r\n")
        asserted = False
        for line in res:
           if line.startswith(" access-list test-cm"):
                self.assertEqual(line, " access-list test-cm-deny imsi-deny ^123[0-9]*$ 42 11")
                asserted = True
        self.assert_(asserted)

        # Check the optional LU Reject Cause
        self.vty.command("access-list test-lu-deny imsi-deny ^123[0-9]*$ 23 42").split("\r\n")
        res = self.vty.command("show running-config").split("\r\n")
        asserted = False
        for line in res:
           if line.startswith(" access-list test-lu"):
                self.assertEqual(line, " access-list test-lu-deny imsi-deny ^123[0-9]*$ 23 42")
                asserted = True
        self.assert_(asserted)


def add_nat_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/osmo-bsc_nat/osmo-bsc_nat")):
        print("Skipping the NAT test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYNAT)
    suite.addTest(test)

def nat_bsc_reload(x):
    x.vty.command("configure terminal")
    x.vty.command("nat")
    x.vty.command("bscs-config-file bscs.cfg")
    x.vty.command("end")

def nat_msc_ip(x, ip, port):
    x.vty.command("configure terminal")
    x.vty.command("nat")
    x.vty.command("msc ip " + ip)
    x.vty.command("msc port " + str(port))
    x.vty.command("end")

def data2str(d):
    return d.encode('hex').lower()

def nat_msc_test(x, ip, port, verbose = False):
    msc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    msc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    msc.settimeout(5)
    msc.bind((ip, port))
    msc.listen(5)
    if (verbose):
        print "MSC is ready at " + ip
    conn = None
    while True:
        vty_response = x.vty.command("show msc connection")
        print "'show msc connection' says: %r" % vty_response
        if vty_response == "MSC is connected: 1":
            # success
            break;
        if vty_response != "MSC is connected: 0":
            raise Exception("Unexpected response to 'show msc connection'"
                            " vty command: %r" % vty_response)

        timeout_retries = 6
        while timeout_retries > 0:
            try:
                conn, addr = msc.accept()
                print "MSC got connection from ", addr
                break
            except socket.timeout:
                print "socket timed out."
                timeout_retries -= 1
                continue

    if not conn:
        raise Exception("VTY reports MSC is connected, but I haven't"
                        " connected yet: %r %r" % (ip, port))
    return msc, conn

def ipa_handle_small(x, verbose = False):
    s = data2str(x.recv(4))
    if len(s) != 4*2:
      raise Exception("expected to receive 4 bytes, but got %d (%r)" % (len(s)/2, s))
    if "0001fe00" == s:
        if (verbose):
            print "\tBSC <- NAT: PING?"
        x.send(IPA().pong())
    elif "0001fe06" == s:
        if (verbose):
            print "\tBSC <- NAT: IPA ID ACK"
        x.send(IPA().id_ack())
    elif "0001fe00" == s:
        if (verbose):
            print "\tBSC <- NAT: PONG!"
    else:
        if (verbose):
            print "\tBSC <- NAT: ", s

def ipa_handle_resp(x, tk, verbose = False, proc=None):
    s = data2str(x.recv(38))
    if "0023fe040108010701020103010401050101010011" in s:
        retries = 3
        while True:
            print "\tsending IPA identity(%s) at %s" % (tk, time.strftime("%T"))
            try:
                x.send(IPA().id_resp(IPA().identity(name = tk.encode('utf-8'))))
                print "\tdone sending IPA identity(%s) at %s" % (tk,
                                                            time.strftime("%T"))
                break
            except:
                print "\tfailed sending IPA identity at", time.strftime("%T")
                if proc:
                  print "\tproc.poll() = %r" % proc.poll()
                if retries < 1:
                    print "\tgiving up"
                    raise
                print "\tretrying (%d attempts left)" % retries
                retries -= 1
    else:
        if (verbose):
            print "\tBSC <- NAT: ", s

def nat_bsc_num_con(x):
    return len(x.vty.command("show bsc connections").split('\n'))

def nat_bsc_sock_test(nr, tk, verbose = False, proc=None):
    bsc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bsc.bind(('127.0.0.1', 0))
    bsc.connect(('127.0.0.1', 5000))
    if (verbose):
        print "BSC%d " %nr
        print "\tconnected to %s:%d" % bsc.getpeername()
    if proc:
      print "\tproc.poll() = %r" % proc.poll()
      print "\tproc.pid = %r" % proc.pid
    ipa_handle_small(bsc, verbose)
    ipa_handle_resp(bsc, tk, verbose, proc=proc)
    if proc:
      print "\tproc.poll() = %r" % proc.poll()
    bsc.recv(27) # MGCP msg
    if proc:
      print "\tproc.poll() = %r" % proc.poll()
    ipa_handle_small(bsc, verbose)
    return bsc

def add_bsc_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/osmo-bsc/osmo-bsc")):
        print("Skipping the BSC test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYBSC)
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
    parser.add_argument("test_name", nargs="*", help="(parts of) test names to run, case-insensitive")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print "confpath %s, workdir %s" % (confpath, workdir)
    os.chdir(workdir)
    print "Running tests for specific VTY commands"
    suite = unittest.TestSuite()
    add_bsc_test(suite, workdir)
    add_nat_test(suite, workdir)

    if args.test_name:
        osmoutil.pick_tests(suite, *args.test_name)

    res = unittest.TextTestRunner(verbosity=verbose_level, stream=sys.stdout).run(suite)
    sys.exit(len(res.errors) + len(res.failures))

# vim: shiftwidth=4 expandtab nocin ai
