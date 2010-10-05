<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    exclude-result-prefixes="str">

  <xsl:output method="text" encoding="string" indent="no" />
  <xsl:strip-space elements="*"/>

<!--
OpenVAS Manager
$Id$
Description: Stylesheet for generating results per threat code for Gnuplot.

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

<xsl:template match="/">
unset title
<xsl:choose>
  <xsl:when test="report/report_format/param[name='Key']/value = '0'">
unset key
  </xsl:when>
  <xsl:otherwise>
set key on outside below
  </xsl:otherwise>
</xsl:choose>
set terminal png size <xsl:value-of select="report/report_format/param[name='Width']/value"/>,<xsl:value-of select="report/report_format/param[name='Height']/value"/>
set boxwidth 0.9 relative
<xsl:choose>
  <xsl:when test="report/report_format/param[name='Fill Style']/value = 'pattern'">
set style fill pattern 2
  </xsl:when>
  <xsl:when test="report/report_format/param[name='Fill Style']/value = 'solid'">
set style fill solid
  </xsl:when>
  <xsl:when test="report/report_format/param[name='Fill Style']/value = 'empty'">
set style fill empty
  </xsl:when>
  <xsl:otherwise>
set style fill empty
  </xsl:otherwise>
</xsl:choose>
set xlabel "Threat"
set ylabel "Results"
set title "<xsl:value-of select="report/report_format/param[name='Title']/value"/>"
show title
set border 11
set xtics nomirror
<xsl:if test="string-length (report/report_format/param[name='Blurb']/value) &gt; 0">
set label "<xsl:value-of select="str:replace (report/report_format/param[name='Blurb']/value, '&#10;', '\n')"/>" at graph 0.5,0.5 center front
</xsl:if>
show label
plot [-0.5:3.5] [0:] 'plot.dat' using 2:xticlabels(1) with boxes linetype 3 fs
exit
</xsl:template>

</xsl:stylesheet>
