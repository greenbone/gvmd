<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:str="http://exslt.org/strings"
  xmlns:func="http://exslt.org/functions"
  xmlns:openvas="http://openvas.org"
  extension-element-prefixes="str func openvas">
  <xsl:output
    method = "text"
    indent = "no" />

<!--
OpenVAS Manager
$Id$
Description:

Authors:
Henri Doreau <henri.doreau@greenbone.net>

Copyright:
Copyright (C) 2011 Greenbone Networks GmbH

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

  <func:function name="openvas:max-cvss">
    <xsl:param name="current_host"/>
    <xsl:variable name="max">
      <xsl:for-each select="/report/results/result[host/text() = $current_host]/nvt/cvss_base">
        <xsl:sort select="." data-type="number" order="descending"/>
        <xsl:if test="position () = 1"><xsl:value-of select="."/></xsl:if>
      </xsl:for-each>
    </xsl:variable>
    <func:result select="$max"/>
  </func:function>

  <func:function name="openvas:ip-pad">
    <xsl:param name="current_host"/>
    <func:result>
      <xsl:for-each select="str:split ($current_host, '.')">
        <xsl:value-of select="format-number (., '000')"/>
      </xsl:for-each>
    </func:result>
  </func:function>

  <xsl:template match="report">
    <xsl:text>IP,Hostname,OS,Scan Start,Scan End,CVSS,Severity,High,Medium,Low,Log,False Positive,Total
</xsl:text>
    <xsl:for-each select="host">
      <xsl:sort select="openvas:max-cvss (ip/text())" data-type="number" order="descending"/>
      <xsl:sort select="openvas:ip-pad (ip/text())" data-type="number" order="ascending"/>
      <xsl:sort select="start/text()"/>

      <xsl:variable name="current_host" select="ip/text()"/>

      <xsl:value-of select="$current_host"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="detail[name/text() = 'hostname']/value/text()"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="detail[name/text() = 'best_os_cpe']/value/text()"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="start/text()"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="end/text()"/>
      <xsl:text>,</xsl:text>

      <xsl:value-of select="openvas:max-cvss ($current_host)"/><xsl:text>,</xsl:text>

      <xsl:variable name="cnt_high"
                    select="count(/report/results/result[host/text() = $current_host][threat/text() = 'High'])"/>
      <xsl:variable name="cnt_medium"
                    select="count(/report/results/result[host/text() = $current_host][threat/text() = 'Medium'])"/>
      <xsl:variable name="cnt_low"
                    select="count(/report/results/result[host/text() = $current_host][threat/text() = 'Low'])"/>
      <xsl:variable name="cnt_log"
                    select="count(/report/results/result[host/text() = $current_host][threat/text() = 'Log'])"/>
      <xsl:variable name="cnt_fp"
                    select="count(/report/results/result[host/text() = $current_host][threat/text() = 'False Positive'])"/>

      <xsl:choose>
        <xsl:when test="$cnt_high > 0">
          <xsl:text>High</xsl:text>
        </xsl:when>
        <xsl:when test="$cnt_medium > 0">
          <xsl:text>Medium</xsl:text>
        </xsl:when>
        <xsl:when test="$cnt_low > 0">
          <xsl:text>Low</xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:text>None</xsl:text>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:text>,</xsl:text>

      <xsl:value-of select="$cnt_high"/><xsl:text>,</xsl:text>
      <xsl:value-of select="$cnt_medium"/><xsl:text>,</xsl:text>
      <xsl:value-of select="$cnt_low"/><xsl:text>,</xsl:text>
      <xsl:value-of select="$cnt_log"/><xsl:text>,</xsl:text>
      <xsl:value-of select="$cnt_fp"/><xsl:text>,</xsl:text>

      <xsl:value-of select="$cnt_high + $cnt_medium + $cnt_low + $cnt_log + $cnt_fp"/>

      <!-- add newline -->
      <xsl:text>
</xsl:text>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
