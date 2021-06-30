# Copyright (C) 2009-2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

message (STATUS "Looking for xsltproc...")

find_program (XSLTPROC_EXECUTABLE xsltproc
              PATHS /bin /usr/bin /usr/local/bin/
              DOC "xsltproc location")

message (STATUS "Looking for xsltproc... ${XSLTPROC_EXECUTABLE}")

## build

set_directory_properties (PROPERTIES CLEAN_NO_CUSTOM true)
set_directory_properties (PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ".built-html;.built-html_full")

include (FindDoxygen)

if (NOT DOXYGEN_EXECUTABLE)
  message (STATUS "WARNING: Doxygen is required to build the HTML docs.")
else (NOT DOXYGEN_EXECUTABLE)
  add_custom_target (doc COMMENT "Building documentation..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gvmd.8 ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/.built-html)

  add_custom_command (OUTPUT .built-html
    COMMAND sh
    ARGS -c \"${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile && touch ${CMAKE_CURRENT_BINARY_DIR}/.built-html\;\"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gvmd.html ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

  add_custom_target (doc-full COMMENT "Building documentation..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gvmd.8 ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_full ${CMAKE_CURRENT_BINARY_DIR}/.built-html_full)

  add_custom_command (OUTPUT .built-html_full
    COMMAND sh
    ARGS -c \"${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_full && touch ${CMAKE_CURRENT_BINARY_DIR}/.built-html_full\;\"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gvmd.html ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_full)

  add_custom_target (doc-xml COMMENT "Building documentation (XML)..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_xml ${CMAKE_CURRENT_BINARY_DIR}/.built-xml)

  add_custom_command (OUTPUT .built-xml
    COMMAND sh
    ARGS -c \"${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_xml && touch ${CMAKE_CURRENT_BINARY_DIR}/.built-xml\;\"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_xml)
endif (NOT DOXYGEN_EXECUTABLE)

if (NOT XSLTPROC_EXECUTABLE)
  message (WARNING "xsltproc is required to build the protocol documentation")
else (NOT XSLTPROC_EXECUTABLE)
  add_custom_target (doc-gmp ALL COMMENT "Building GMP documentation..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gmp.rnc ${CMAKE_CURRENT_BINARY_DIR}/gmp.html)

  add_custom_command (OUTPUT gmp.rnc
    COMMAND sh
    ARGS -c \"cd ${CMAKE_SOURCE_DIR}/src/schema_formats/RNC && ${XSLTPROC_EXECUTABLE} ./RNC.xsl ${CMAKE_BINARY_DIR}/src/schema_formats/XML/GMP.xml > ${CMAKE_BINARY_DIR}/doc/gmp.rnc\;\"
    DEPENDS
    ${CMAKE_BINARY_DIR}/src/schema_formats/XML/GMP.xml
    ${CMAKE_SOURCE_DIR}/src/schema_formats/RNC/generate
    ${CMAKE_SOURCE_DIR}/src/schema_formats/RNC/RNC.xsl
    ${CMAKE_SOURCE_DIR}/src/schema_formats/rnc.xsl)

  add_custom_command (OUTPUT gmp.html
    COMMAND sh
    ARGS -c \"cd ${CMAKE_SOURCE_DIR}/src/schema_formats/HTML && ${XSLTPROC_EXECUTABLE} ./HTML.xsl ${CMAKE_BINARY_DIR}/src/schema_formats/XML/GMP.xml > ${CMAKE_BINARY_DIR}/doc/gmp.html\;\"
    DEPENDS
    ${CMAKE_BINARY_DIR}/src/schema_formats/XML/GMP.xml
    ${CMAKE_SOURCE_DIR}/src/schema_formats/HTML/generate
    ${CMAKE_SOURCE_DIR}/src/schema_formats/HTML/HTML.xsl
    ${CMAKE_SOURCE_DIR}/src/schema_formats/rnc.xsl)
endif (NOT XSLTPROC_EXECUTABLE)

if (XMLTOMAN_EXECUTABLE)
  add_custom_target (man COMMENT "Building manual page..."
    DEPENDS gvmd.8 greenbone-certdata-sync.8 greenbone-scapdata-sync.8)

  add_custom_command (OUTPUT gvmd.8
					  COMMAND sh
					  ARGS -c \"${XMLTOMAN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gvmd.8.xml > ${CMAKE_CURRENT_BINARY_DIR}/gvmd.8\;\"
					  DEPENDS gvmd.8.xml)

  add_custom_command (OUTPUT greenbone-certdata-sync.8
					  COMMAND sh
					  ARGS -c \"${XMLTOMAN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/greenbone-certdata-sync.8.xml > ${CMAKE_CURRENT_BINARY_DIR}/greenbone-certdata-sync.8\;\"
					  DEPENDS greenbone-certdata-sync.8.xml)

  add_custom_command (OUTPUT greenbone-scapdata-sync.8
					  COMMAND sh
					  ARGS -c \"${XMLTOMAN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/greenbone-scapdata-sync.8.xml > ${CMAKE_CURRENT_BINARY_DIR}/greenbone-scapdata-sync.8\;\"
					  DEPENDS greenbone-scapdata-sync.8.xml)
else (XMLTOMAN_EXECUTABLE)
  message (STATUS "WARNING: xmltoman is required to generate manpage.")
  add_custom_command (OUTPUT gvmd.8
                      COMMAND echo "[Error: xmltoman required to see manpage here]"
					          > gvmd.8)
  add_custom_command (OUTPUT greenbone-certdata-sync.8
                      COMMAND echo "[Error: xmltoman required to see manpage here]"
					          > greenbone-certdata-sync.8)
  add_custom_command (OUTPUT greenbone-scapdata-sync.8
                      COMMAND echo "[Error: xmltoman required to see manpage here]"
					          > greenbone-scapdata-sync.8)
endif (XMLTOMAN_EXECUTABLE)

if (XMLMANTOHTML_EXECUTABLE)
  add_custom_target (man-html COMMENT "Building manual page HTML..."
    DEPENDS gvmd.html)

  add_custom_command (OUTPUT gvmd.html
					  COMMAND sh
					  ARGS -c \"${XMLMANTOHTML_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gvmd.8.xml > ${CMAKE_CURRENT_BINARY_DIR}/gvmd.html\;\"
					  DEPENDS gvmd.8.xml)
else (XMLMANTOHTML_EXECUTABLE)
  message (STATUS "WARNING: xmlmantohtml is required for manpage in HTML docs.")
  add_custom_command (OUTPUT gvmd.html
                      COMMAND echo "[Error: xmlmantohtml required to see manpage here]"
					          > gvmd.html)
endif (XMLMANTOHTML_EXECUTABLE)

## Install

if (XSLTPROC_EXECUTABLE)
  install (FILES ${CMAKE_CURRENT_BINARY_DIR}/gmp.html
    DESTINATION share/doc/gvm/html/
    COMPONENT doc)
endif (XSLTPROC_EXECUTABLE)

install (FILES gvmd.8 greenbone-certdata-sync.8 greenbone-scapdata-sync.8
  DESTINATION share/man/man8/
  COMPONENT doc)
