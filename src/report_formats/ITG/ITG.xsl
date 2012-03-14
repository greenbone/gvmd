<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:output method="text" encoding="UTF-8" />

<!--
OpenVAS Manager
$Id$
Description: Report stylesheet for IT-Grundschutz CSV format.

This stylesheet extracts the tables of IT-Grundschutz
scans from the given XML scan report using a XSL
transformation with the tool xsltproc.

Authors:
Matthew Mundell <matthew.mundell@greenbone.net>

Copyright:
Copyright (C) 2010 Greenbone Networks GmbH

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

<xsl:template match="report">
  <xsl:choose>
    <xsl:when test = "@extension = 'xml'">
      <xsl:apply-templates select="report"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:apply-templates
        select="results/result[port='general/IT-Grundschutz-T']/description"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="/">
  <xsl:apply-templates select="report"/>
</xsl:template>

</xsl:stylesheet>
