# OpenVAS
# $Id$
# Description: joins threat data to coordinatesbased on IP as key.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

BEGIN   { FS=","
          countLocations = 0
          countHosts = 0
        }

NF == 4 { # hits locations.csv
          locations[$1, "lon"] = $2
          locations[$1, "lat"] = $3
          locations[$1, "comment"] = $4
          countLocations ++
        }

NF == 5 { # hits hosts.csv
          hosts[countHosts, "IP"] = $1
          hosts[countHosts, "high"] = $2
          hosts[countHosts, "medium"] = $3
          hosts[countHosts, "low"] = $4
          hosts[countHosts, "color"] = $5
          countHosts ++
        }

END     {
          for (i = 0;i < countHosts;i ++)
            {
              if (locations[hosts[i, "IP"], "lon"] != "")
                printf("%s,%s,%s,%s,%s,%s,%s,%s\n", hosts[i, "IP"],
                                     locations[hosts[i, "IP"], "lon"],
                                     locations[hosts[i, "IP"], "lat"],
                                     locations[hosts[i, "IP"], "comment"],
                                     hosts[i, "high"],
                                     hosts[i, "medium"],
                                     hosts[i, "low"],
                                     hosts[i, "color"])
              if (locations[hosts[i, "IP"]] == "127.0.0.1")
                printf ("%s,%s,%s,%s,%s,%s,%s,%s\n", hosts[i, "IP"],
                                     locations[hosts[i, "IP"], "lon"],
                                     locations[hosts[i, "IP"], "lat"],
                                     locations[hosts[i, "IP"], "comment"],
                                     "0", "0", "0", "white")
            }
        }
