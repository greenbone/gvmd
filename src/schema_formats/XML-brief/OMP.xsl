<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:func = "http://exslt.org/functions"
    extension-element-prefixes="str func">

<!--
OpenVAS Manager
$Id$
Description: OpenVAS Manager Protocol (OMP) single page HTML doc generator.

Authors:
Matthew Mundell <matthew.mundell@greenbone.de>

Copyright:
Copyright (C) 2010, 2012 Greenbone Networks GmbH

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

  <xsl:template match="command">
    <command>
      <name><xsl:value-of select="name"/></name>
      <summary><xsl:value-of select="summary"/></summary>
    </command>
  </xsl:template>

  <!-- Root. -->

  <xsl:template match="protocol">
    <protocol>
      <name><xsl:value-of select="name"/></name>
      <abbreviation><xsl:value-of select="abbreviation"/></abbreviation>
      <summary><xsl:value-of select="summary"/></summary>
      <version><xsl:value-of select="version"/></version>
      <xsl:apply-templates select="command"/>
    </protocol>
  </xsl:template>

  <xsl:template match="/">
    <xsl:apply-templates select="protocol"/>
  </xsl:template>

</xsl:stylesheet>
