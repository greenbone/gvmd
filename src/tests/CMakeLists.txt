# OpenVAS
# $Id$
# Description: CMakefile for the tests of the OpenVAS Manager program
#
# Authors:
# Matthew Mundell <matt@mundell.ukfsn.org>
#
# Copyright:
# Copyright (C) 2008 Intevation GmbH
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

## Programs

add_executable (strip_space_0 strip_space_0.c)
target_link_libraries (strip_space_0 string)
set_target_properties (strip_space_0 PROPERTIES COMPILE_FLAGS "-I ..")
ADD_TEST (strip_space_0 strip_space_0)

add_executable (strip_space_1 strip_space_1.c)
target_link_libraries (strip_space_1 string)
set_target_properties (strip_space_1 PROPERTIES COMPILE_FLAGS "-I ..")
ADD_TEST (strip_space_1 strip_space_1)

add_executable (strip_space_2 strip_space_2.c)
target_link_libraries (strip_space_2 string)
set_target_properties (strip_space_2 PROPERTIES COMPILE_FLAGS "-I ..")
ADD_TEST (strip_space_2 strip_space_2)

add_executable (strip_space_3 strip_space_3.c)
target_link_libraries (strip_space_3 string)
set_target_properties (strip_space_3 PROPERTIES COMPILE_FLAGS "-I ..")
ADD_TEST (strip_space_3 strip_space_3)

## End
