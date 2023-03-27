<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:func = "http://exslt.org/functions"
    extension-element-prefixes="str func">

<!--
Copyright (C) 2010-2022 Greenbone AG

SPDX-License-Identifier: AGPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->

<!-- Greenbone Management Protocol (GMP) single page HTML doc generator. -->

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
