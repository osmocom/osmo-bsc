#!/usr/bin/env python

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

app_configs = {
    "osmo-bsc": ["doc/examples/osmo-bsc/osmo-bsc.cfg",
                 "doc/examples/osmo-bsc/osmo-bsc_custom-sccp.cfg"],
    "nat": ["doc/examples/osmo-bsc_nat/osmo-bsc_nat.cfg"],
}

apps = [(4242, "src/osmo-bsc/osmo-bsc", "OsmoBSC", "osmo-bsc"),
        (4244, "src/osmo-bsc_nat/osmo-bsc_nat",  "OsmoBSCNAT", "nat"),
        ]

vty_command = ["./src/osmo-bsc/osmo-bsc", "-c",
               "doc/examples/osmo-bsc/osmo-bsc.cfg"]

vty_app = apps[0]
