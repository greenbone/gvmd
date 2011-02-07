# OpenVAS
# $Id$
# Description: CMakefile for the OpenVAS Manager documentation
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

message (STATUS "Looking for SQLFairy...")

find_program (SQLT-DIAGRAM_EXECUTABLE sqlt-diagram
              PATHS /bin /usr/bin /usr/local/bin/
              DOC "sqlt-diagram location")

find_program (SQLT_EXECUTABLE sqlt
              PATHS /bin /usr/bin /usr/local/bin/
              DOC "sqlt location")

message (STATUS "Looking for SQLFairy... ${SQLT-DIAGRAM_EXECUTABLE}, ${SQLT_EXECUTABLE}")

## build

set_directory_properties (PROPERTIES CLEAN_NO_CUSTOM true)
set_directory_properties (PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ".built-html;.built-html_full")

include (FindDoxygen)

if (NOT DOXYGEN_EXECUTABLE)
  message (STATUS "WARNING: Doxygen is required to build the HTML docs.")
else (NOT DOXYGEN_EXECUTABLE)
  set (DOC_FILES
    ../src/openvasmd.c ../src/ovas-mngr-comm.c
    ../src/oxpd.c ../src/ompd.c ../src/otpd.c
    ../src/manage.c ../src/omp.c ../src/otp.c
    ../src/manage_sql.c ../src/tracef.h
    ../src/logf.h ../src/tests/common.c
    ../README ../INSTALL)

  add_custom_target (doc COMMENT "Building documentation..."
    DEPENDS openvasmd.8 Doxyfile .built-html .built-html_db
    db.png omp.rnc omp.html)

  add_custom_target (doc-full COMMENT "Building documentation..."
    DEPENDS openvasmd.8 Doxyfile_full .built-html_full
    .built-html_db db.png omp.rnc omp.html)
endif (NOT DOXYGEN_EXECUTABLE)

if (XMLTOMAN_EXECUTABLE)
  add_custom_target (man COMMENT "Building manual page..."
    DEPENDS openvasmd.8)

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
  add_custom_target (man-html COMMENT "Building manual page HTML..."
    DEPENDS openvasmd.html)

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

if (SQLT-DIAGRAM_EXECUTABLE)
  add_custom_command (OUTPUT db.png
					  COMMAND sh
					  ARGS -c \"${SQLT-DIAGRAM_EXECUTABLE} --color --title=\\\"Manager database \(version ${OPENVASMD_DATABASE_VERSION}\)\\\" -d PostgreSQL db_postgres.sql -o db.png\;\"
					  DEPENDS db_postgres.sql)
else (SQLT_EXECUTABLE)
  add_custom_command (OUTPUT db.png
					  COMMAND sh
					  ARGS -c \"touch db.png;\")
endif (SQLT-DIAGRAM_EXECUTABLE)

if (SQLT_EXECUTABLE)
  add_custom_command (OUTPUT .built-html_db
					  COMMAND sh
					  ARGS -c \"${SQLT_EXECUTABLE} --from PostgreSQL --to HTML --pretty --title=\\\"Manager database \(version ${OPENVASMD_DATABASE_VERSION}\)\\\" db_postgres.sql > db.html && touch .built-html_db\;\"
					  DEPENDS db_postgres.sql)
else (SQLT_EXECUTABLE)
  add_custom_command (OUTPUT .built-html_db
					  COMMAND sh
					  ARGS -c \"echo \\\"[Error: sqlt, from SQLFairy, required to see database here]\\\" > db.html && touch .built-html_db\;\")
endif (SQLT_EXECUTABLE)

add_custom_command (OUTPUT .built-html
                    COMMAND sh
					ARGS -c \"cd .. && ${DOXYGEN_EXECUTABLE} doc/Doxyfile && touch doc/.built-html\;\"
					DEPENDS openvasmd.html Doxyfile ${DOC_FILES})

add_custom_command (OUTPUT .built-html_full
                    COMMAND sh
					ARGS -c \"cd .. && ${DOXYGEN_EXECUTABLE} doc/Doxyfile_full && touch doc/.built-html_full\;\"
					DEPENDS openvasmd.html Doxyfile_full ${DOC_FILES})

add_custom_command (OUTPUT omp.rnc
                    COMMAND sh
					ARGS -c \"cd ../src/schema_formats/RNC && . ./generate ../XML/OMP.xml > ../../../doc/omp.rnc\;\"
					DEPENDS
					../src/schema_formats/XML/OMP.xml
					../src/schema_formats/RNC/generate
					../src/schema_formats/RNC/RNC.xsl
					../src/schema_formats/RNC/rnc.xsl)

add_custom_command (OUTPUT omp.html
                    COMMAND sh
					ARGS -c \"cd ../src/schema_formats/HTML && . ./generate ../XML/OMP.xml > ../../../doc/omp.html\;\"
					DEPENDS
					../src/schema_formats/XML/OMP.xml
					../src/schema_formats/HTML/generate
					../src/schema_formats/HTML/HTML.xsl
					../src/schema_formats/HTML/rnc.xsl)

## Install

# file (MAKE_DIRECTORY html/)

# install (DIRECTORY html/
#         DESTINATION share/doc/openvas-manager/html/
#         COMPONENT doc)

install (FILES openvasmd.8
  DESTINATION share/man/man8/
  COMPONENT doc)
