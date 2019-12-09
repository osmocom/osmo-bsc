#!/usr/bin/env python3

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
                 "doc/examples/osmo-bsc/osmo-bsc_custom-sccp.cfg"]
}

apps = [(4242, "src/osmo-bsc/osmo-bsc", "OsmoBSC", "osmo-bsc")
        ]

vty_command = ["./src/osmo-bsc/osmo-bsc", "-c",
               "doc/examples/osmo-bsc/osmo-bsc.cfg"]

vty_app = apps[0]
