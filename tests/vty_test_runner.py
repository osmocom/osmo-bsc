#!/usr/bin/env python3

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
from osmopy.osmo_ipa import IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')

class TestVTYBase(unittest.TestCase):

    def checkForEndAndExit(self):
        res = self.vty.command("list")
        #print ('looking for "exit"\n')
        self.assertTrue(res.find('  exit\r') > 0)
        #print 'found "exit"\nlooking for "end"\n'
        self.assertTrue(res.find('  end\r') > 0)
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
            print("Current directory: %s" % os.getcwd(), file=sys.stderr)
            print("Consider setting -b", file=sys.stderr)

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
        self.assertEqual(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("network",['']))
        self.assertEqual(self.vty.node(), 'config-net')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("bts 0",['']))
        self.assertEqual(self.vty.node(), 'config-net-bts')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("trx 0",['']))
        self.assertEqual(self.vty.node(), 'config-net-bts-trx')
        self.checkForEndAndExit()
        self.vty.command("write terminal")
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEqual(self.vty.node(), 'config-net-bts')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertTrue(self.vty.verify("bts 1",['']))
        self.assertEqual(self.vty.node(), 'config-net-bts')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("trx 1",['']))
        self.assertEqual(self.vty.node(), 'config-net-bts-trx')
        self.checkForEndAndExit()
        self.vty.command("write terminal")
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEqual(self.vty.node(), 'config-net-bts')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEqual(self.vty.node(), 'config-net')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEqual(self.vty.node(), 'config')
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
        self.assertEqual(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("msc 0", ['']))
        self.assertEqual(self.vty.node(), 'config-msc')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertEqual(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("bsc", ['']))
        self.assertEqual(self.vty.node(), 'config-bsc')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertEqual(self.vty.node(), 'config')
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
        self.assertTrue(res.find('bsc-msc-lost-text MSC disconnected') > 0)
        self.assertEqual(res.find('no bsc-msc-lost-text'), -1)
        self.assertTrue(res.find('bsc-welcome-text Hello MS') > 0)
        self.assertEqual(res.find('no bsc-welcome-text'), -1)
        self.assertTrue(res.find('bsc-grace-text In grace period') > 0)
        self.assertEqual(res.find('no bsc-grace-text'), -1)

        # Now disable it..
        self.vty.verify("no bsc-msc-lost-text", [''])
        self.vty.verify("no bsc-welcome-text", [''])
        self.vty.verify("no bsc-grace-text", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEqual(res.find('bsc-msc-lost-text MSC disconnected'), -1)
        self.assertTrue(res.find('no bsc-msc-lost-text') > 0)
        self.assertEqual(res.find('bsc-welcome-text Hello MS'), -1)
        self.assertTrue(res.find('no bsc-welcome-text') > 0)
        self.assertEqual(res.find('bsc-grace-text In grace period'), -1)
        self.assertTrue(res.find('no bsc-grace-text') > 0)

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
        self.assertTrue(res.find('missing-msc-text No MSC found') > 0)
        self.assertEqual(res.find('no missing-msc-text'), -1)

        # Now disable it..
        self.vty.verify("no missing-msc-text", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEqual(res.find('missing-msc-text No MSC found'), -1)
        self.assertTrue(res.find('no missing-msc-text') > 0)

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
        self.assertTrue(res.find('timezone 2 30') > 0)
        self.assertEqual(res.find('timezone 2 30 '), -1)

        # Set time zone with DST
        self.vty.verify("timezone 2 30 1", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertTrue(res.find('timezone 2 30 1') > 0)

        # Now disable it..
        self.vty.verify("no timezone", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEqual(res.find(' timezone'), -1)

    def testShowNetwork(self):
        res = self.vty.command("show network")
        self.assertTrue(res.startswith('BSC is on Country Code') >= 0)

    def testMscDataCoreLACCI(self):
        self.vty.enable()
        res = self.vty.command("show running-config")
        self.assertEqual(res.find("core-location-area-code"), -1)
        self.assertEqual(res.find("core-cell-identity"), -1)

        self.vty.command("configure terminal")
        self.vty.command("msc 0")
        self.vty.command("core-location-area-code 666")
        self.vty.command("core-cell-identity 333")

        res = self.vty.command("show running-config")
        self.assertTrue(res.find("core-location-area-code 666") > 0)
        self.assertTrue(res.find("core-cell-identity 333") > 0)


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

    print("confpath %s, workdir %s" % (confpath, workdir))
    os.chdir(workdir)
    print("Running tests for specific VTY commands")
    suite = unittest.TestSuite()
    add_bsc_test(suite, workdir)

    if args.test_name:
        osmoutil.pick_tests(suite, *args.test_name)

    res = unittest.TextTestRunner(verbosity=verbose_level, stream=sys.stdout).run(suite)
    sys.exit(len(res.errors) + len(res.failures))

# vim: shiftwidth=4 expandtab nocin ai
