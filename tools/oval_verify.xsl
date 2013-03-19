<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Verification that a given XML file contains basic OVAL elements.

Authors:
Timo Pollmeier <timo.pollmeier@greenbone.net>

Copyright:
Copyright (C) 2013 Greenbone Networks GmbH

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2,
or, at your option, any later version as published by the Free
Software Foundation

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
-->
<xsl:stylesheet version="1.0" 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:str="http://exslt.org/strings"
  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
  xmlns:oval_definitions="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xsi:schemaLocation="http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-common-schema.xsd http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-definitions-schema.xsd"
  extension-element-prefixes="str"
  >
  <xsl:output method="text"/>

  <xsl:template match="/">
  <xsl:if test="count(oval_definitions:oval_definitions/oval_definitions:definitions/oval_definitions:definition) = 0">No OVAL definitions found<xsl:message terminate="yes"/></xsl:if>
  <xsl:text>file valid</xsl:text>
  </xsl:template>

</xsl:stylesheet>
