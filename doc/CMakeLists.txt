# OpenVAS
# $Id$
# Description: CMakefile for the OpenVAS Manager documentation
#
# Authors:
# Matthew Mundell <matt@mundell.ukfsn.org>
#
# Copyright:
# Copyright (C) 2008 Intevation GmbH
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

## Check groff

message (STATUS "Looking for groff...")

find_program (GROFF_EXECUTABLE groff
              PATHS /bin /usr/bin /usr/local/bin/
              DOC "Groff location")

message (STATUS "Looking for groff... ${GROFF_EXECUTABLE}")

# if (GROFF_EXECUTABLE)
#   message (STATUS "Checking if groff does HTML...")
#   execute_process (COMMAND echo test | ${GROFF_EXECUTABLE} -T html
#                    RESULT_VARIABLE GROFF_DOES_HTML
# 				   OUTPUT_QUIET ERROR_QUIET)
#
#   if ("${GROFF_DOES_HTML}" MATCHES "^0$")
#     set (GROFF_DOES_HTML true)
#   else ("${GROFF_DOES_HTML}" MATCHES "^0$")
#     set (GROFF_DOES_HTML false)
#   endif ("${GROFF_DOES_HTML}" MATCHES "^0$")
#
#   message (STATUS "Checking if groff does HTML... ${GROFF_DOES_HTML}")
# endif (GROFF_EXECUTABLE)

## Find xml2man

message (STATUS "Looking for xmltoman...")

find_program (XMLTOMAN_EXECUTABLE xmltoman
              PATHS /bin /usr/bin /usr/local/bin/
              DOC "xmltoman location")

message (STATUS "Looking for xmltoman... ${XMLTOMAN_EXECUTABLE}")

find_program (XMLMANTOHTML_EXECUTABLE xmlmantohtml
              PATHS /bin /usr/bin /usr/local/bin/
              DOC "xmlmantohtml location")

message (STATUS "Looking for xmlmantohtml... ${XMLMANTOHTML_EXECUTABLE}")

# FIX find_program seems to follow symlink
if (XMLMANTOHTML_EXECUTABLE)
  set (XMLMANTOHTML_EXECUTABLE xmlmantohtml)
endif (XMLMANTOHTML_EXECUTABLE)

## build

include (FindDoxygen)

if (NOT DOXYGEN_EXECUTABLE)
  message (FATAL_ERROR "Doxygen is required to build the HTML docs.")
endif (NOT DOXYGEN_EXECUTABLE)

add_custom_target (doc COMMENT "Building documentation..."
                   DEPENDS openvasmd.8 Doxyfile .built-html)

if (XMLTOMAN_EXECUTABLE)
  add_custom_command (OUTPUT openvasmd.8
					  COMMAND sh
					  ARGS -c \"${XMLTOMAN_EXECUTABLE} openvasmd.8.xml > openvasmd.8\;\"
					  DEPENDS openvasmd.8.xml)
else (XMLTOMAN_EXECUTABLE)
  message (STATUS "WARNING: xmltoman is required to generate manpage.")
  add_custom_command (OUTPUT openvasmd.8
                      COMMAND echo "[Error: xmltoman required to see manpage here]"
					          > openvasmd.8)
endif (XMLTOMAN_EXECUTABLE)

if (XMLMANTOHTML_EXECUTABLE)
  add_custom_command (OUTPUT openvasmd.html
					  COMMAND sh
					  ARGS -c \"${XMLMANTOHTML_EXECUTABLE} openvasmd.8.xml > openvasmd.html\;\"
					  DEPENDS openvasmd.8.xml)
else (XMLMANTOHTML_EXECUTABLE)
  message (STATUS "WARNING: xmlmantohtml is required for manpage in HTML docs.")
  add_custom_command (OUTPUT openvasmd.html
                      COMMAND echo "[Error: xmlmantohtml required to see manpage here]"
					          > openvasmd.html)
endif (XMLMANTOHTML_EXECUTABLE)

add_custom_command (OUTPUT .built-html
                    COMMAND sh
					ARGS -c \"cd .. && ${DOXYGEN_EXECUTABLE} doc/Doxyfile && touch doc/.built-html\;\"
					DEPENDS openvasmd.html Doxyfile footer.html
					        ../src/openvasmd.c ../src/ovas-mngr-comm.c
							../src/ompd.c ../src/otpd.c
							../src/manage.c ../src/omp.c ../src/otp.c
							../src/string.c ../src/file.c ../src/tracef.h
							../src/logf.h ../src/tests/common.c
							../README ../INSTALL)

# if (GROFF_DOES_HTML)
#   add_custom_command (OUTPUT openvasmd.html
# 					  COMMAND sh
# 					  ARGS -c \"${GROFF_EXECUTABLE} -T html openvasmd.8 > openvasmd.html\;\"
# 					  DEPENDS openvasmd.8)
#   add_custom_command (OUTPUT .built-html
# 					  COMMAND sh
# 					  ARGS -c \"${DOXYGEN_EXECUTABLE} Doxyfile && touch .built-html\;\"
# 					  DEPENDS openvasmd.html Doxyfile footer.html
# 					          ../src/openvasmd.c
# 							  ../README ../INSTALL)
# else (GROFF_DOES_HTML)
#   message (STATUS "WARNING: groff with HTML device is required for manpage in HTML docs.")
#   add_custom_command (OUTPUT openvasmd.html
#                       COMMAND echo "[Error: groff with HTML device is required to see manpage here]"
# 					          > openvasmd.html)
#   add_custom_command (OUTPUT .built-html
# 					  COMMAND sh
# 					  ARGS -c \"${DOXYGEN_EXECUTABLE} Doxyfile && touch .built-html\;\"
# 					  DEPENDS openvasmd.html Doxyfile footer.html
# 					          ../src/openvasmd.c
# 							  ../README ../INSTALL)
# endif (GROFF_DOES_HTML)


## Install

file (MAKE_DIRECTORY html/)

install (DIRECTORY html/
         DESTINATION share/doc/openvas-manager/html/
         COMPONENT doc)

if (XMLTOMAN_EXECUTABLE)
  install (FILES openvasmd.8
		   DESTINATION share/man/man8/
		   COMPONENT doc)
endif (XMLTOMAN_EXECUTABLE)
