<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:date="http://exslt.org/dates-and-times"
    xmlns:openvas="http://openvas.org"
    exclude-result-prefixes="str date">
  <xsl:output method="text" encoding="string" indent="no"/>
  <xsl:strip-space elements="*"/>

<!--
OpenVAS Manager
$Id$
Description: Report stylesheet for NBE format.

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

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template name="ctime">
    <xsl:param name="date" select="text()"/>
    <xsl:choose>
      <xsl:when test="string-length ($date) &gt; 0">
        <xsl:value-of select="concat (date:day-abbreviation ($date), ' ', date:month-abbreviation ($date), ' ', date:day-in-month ($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ':', format-number(date:second-in-minute($date), '00'), ' ', date:year($date))"/>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

<xsl:template match="scan_start">timestamps|||scan_start|<xsl:call-template name="ctime"/>|</xsl:template>

<xsl:template match="scan_end">timestamps|||scan_end|<xsl:call-template name="ctime"/>|</xsl:template>

<xsl:template match="threat">
  <xsl:choose>
    <xsl:when test="text()='Low'">Security Note</xsl:when>
    <xsl:when test="text()='Medium'">Security Warning</xsl:when>
    <xsl:when test="text()='High'">Security Hole</xsl:when>
    <xsl:otherwise>Log Message</xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="nvt/tags">
  <xsl:value-of select="substring-after('.', 'cvss_base_vector=')"/>
</xsl:template>

<xsl:template match="result">
  <xsl:variable name="cve_ref">
    <xsl:if test="nvt/cve != '' and nvt/cve != 'NOCVE'">
      <xsl:value-of select="nvt/cve/text()"/>
    </xsl:if>
  </xsl:variable>
  <xsl:variable name="bid_ref">
    <xsl:if test="nvt/bid != '' and nvt/bid != 'NOBID'">
      <xsl:value-of select="nvt/bid/text()"/>
    </xsl:if>
  </xsl:variable>
  <xsl:variable name="xref">
    <xsl:if test="nvt/xref != '' and nvt/xref != 'NOXREF'">
      <xsl:value-of select="nvt/xref/text()"/>
    </xsl:if>
  </xsl:variable>
  <xsl:variable name="cvss_base_vector">
    <xsl:for-each select="str:split (nvt/tags, '|')">
      <xsl:if test="'cvss_base_vector' = substring-before (., '=')">
        <xsl:value-of select="substring-after (., '=')"/>
      </xsl:if>
    </xsl:for-each>
  </xsl:variable>
results|<xsl:value-of select="host"/>|<xsl:value-of select="host"/>|<xsl:value-of select="port"/>|<xsl:value-of select="str:replace(nvt/@oid, '1.3.6.1.4.1.25623.1.0.', '')"/>|<xsl:apply-templates select="threat"/>|<xsl:value-of select="str:replace(description, '&#10;', '\n')"/>\n<xsl:if test="nvt/cvss_base != ''">Risk factor :\n\n<xsl:value-of select="nvt/risk_factor"/> / CVSS Base Score : <xsl:value-of select="nvt/cvss_base"/>\n(CVSS2#:<xsl:value-of select="$cvss_base_vector"/>)\n<xsl:if test="$cve_ref != ''">\nCVE : <xsl:value-of select="$cve_ref"/>\n</xsl:if><xsl:if test="$bid_ref != ''">\nBID : <xsl:value-of select="$bid_ref"/>\n</xsl:if><xsl:if test="$xref != ''">\nOther references : <xsl:value-of select="$xref"/>\n</xsl:if></xsl:if>
</xsl:template>

<xsl:template match="report">
<xsl:apply-templates select="scan_start"/>
<xsl:for-each select="host_start"><xsl:variable name="host"><xsl:value-of select="host/text()"/></xsl:variable>
timestamps||<xsl:value-of select="$host"/>|host_start|<xsl:call-template name="ctime"/>|<xsl:apply-templates select="../results/result[host/text()=$host]"/>
timestamps||<xsl:value-of select="$host"/>|host_end|<xsl:call-template name="ctime" select="../host_end[host/text()=$host]/text()"/>|</xsl:for-each>
<!-- TODO Was start, end, start, end... in 1.0. -->
<xsl:apply-templates select="scan_end"/>
<xsl:call-template name="newline"/>
</xsl:template>

<xsl:template match="/">
  <xsl:choose>
    <xsl:when test = "report/@extension = 'xml'">
      <xsl:apply-templates select="report/report"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:apply-templates select="report"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

</xsl:stylesheet>
