#!/usr/bin/gnuplot
#
# OpenVAS
# $Id$
# Description: Report generator script: CPE.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
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

unset title
unset key
set terminal png
set boxwidth 0.9 relative
set style fill pattern 2
set xlabel "Threat"
set ylabel "Results"
set title "Results per Threat"
set border 11
set xtics nomirror
plot [-0.5:3.5] [0:] 'plot.dat' using 2:xticlabels(1) with boxes linetype 3 fs
exit
