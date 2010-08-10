# OpenVAS
# $Id$
# Description: CMakefile for the tests of the OpenVAS Manager export generators
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
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

## Testing output of report generators

add_test (nbe_report_base   test_report_format  NBE  report_base)
add_test (txt_report_base   test_report_format  TXT  report_base)

## End
