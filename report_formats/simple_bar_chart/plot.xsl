<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:func = "http://exslt.org/functions"
    xmlns:openvas="http://openvas.org"
    extension-element-prefixes="func">

  <xsl:output method="text" encoding="UTF-8" />

<!--
OpenVAS Manager
$Id$
Description: Stylesheet for generating results per threat data for Gnuplot.

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

  <func:function name="openvas:report">
    <xsl:choose>
      <xsl:when test="count(/report/report) &gt; 0">
        <func:result select="/report/report"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="/report"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

<xsl:template match="/">
High <xsl:value-of select="count (openvas:report()/results/result[threat='High'])"/>
Medium <xsl:value-of select="count (openvas:report()/results/result[threat='Medium'])"/>
Low <xsl:value-of select="count (openvas:report()/results/result[threat='Low'])"/>
Log <xsl:value-of select="count (openvas:report()/results/result[threat='Log'])"/>
</xsl:template>

</xsl:stylesheet>
