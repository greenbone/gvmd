<?xml version="1.0"?>
<!--
$Id$
Description: Sourcefire Export Stylesheet

Authors:
Felix Wolfsteller <felix.wolfsteller@greenbone.net>
Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>

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

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text"
            encoding="string"/>

<!-- PORT FROM PORT ELEMENT
  Example inputs are:
  https (443/tcp)
  nfs (2049/udp)
  general/tcp
  Note however that these formats are conventions only and
  not enforced by OpenVAS.
-->
<xsl:template name="portport">
  <xsl:variable name="before_slash" select="substring-before(port, '/')" />
  <xsl:variable name="port_nr" select="substring-after($before_slash, '(')" />
  <xsl:value-of select="$port_nr"/>
</xsl:template>

<!-- PROTOCOL FROM PORT ELEMENT
  Example inputs are:
  https (443/tcp)
  nfs (2049/udp)
  general/tcp
  Note however that these formats are conventions only and
  not enforced by OpenVAS.
-->
<xsl:template name="portproto">
  <xsl:variable name="after_slash" select="substring-after(port, '/')" />
  <xsl:variable name="port_proto" select="substring-before($after_slash, ')')" />
  <xsl:value-of select="$port_proto"/>
</xsl:template>

<!-- RECURSE COMMA-SEPARATED BID LIST -->
<xsl:template name="bid_recurse">
  <xsl:param name="bid_list"/>
  <xsl:variable name="space"> </xsl:variable>
  <xsl:choose>
    <!-- multiple BIDs -->
    <xsl:when test="contains($bid_list, ',')">
      <xsl:variable name="head" select="substring-before($bid_list, ',')" />
      <xsl:variable name="tail" select="substring-after($bid_list, ',')"/>
      <xsl:value-of select="$space"/><xsl:value-of select="$head"/>
      <xsl:call-template name="bid_recurse">
        <xsl:with-param name="bid_list" select="$tail"/>
      </xsl:call-template>
    </xsl:when>
    <!-- single BID -->
    <xsl:otherwise>
      <xsl:value-of select="$space"/><xsl:value-of select="$bid_list"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- BIDS AS SPACE SEPARATED STRING FROM DESCRIPTION ELEMENT
  Example input is:
  Lengthy description of NVT...
  continues...
  BID : 32383, 32625, 32688
  other tags...
-->
<xsl:template name="bids">
  <xsl:choose>
    <xsl:when test="contains(description, 'BID : ')">
      <xsl:variable name="after_bid" select="substring-after(description, 'BID : ')" />
      <xsl:variable name="bid_comma" select="substring-before($after_bid, '&#xA;')" />
      <!-- recurse in comma separated list and output BID IDS. -->
      <xsl:call-template name="bid_recurse">
        <xsl:with-param name="bid_list" select="$bid_comma"/>
      </xsl:call-template>
    </xsl:when>
  <xsl:otherwise>
  </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- DESCRIPTION TEXT, DOUBLE QUOTES REPLACED BY SINGLE QUOTES
<xsl:template name="quote_replace_recurse">
  <xsl:param name="string_to_quote"/>
  <xsl:when test="contains($string_to_quote, '\"')">
  </xsl:when>
</xsl:template>-->

<!-- MATCH RESULT -->
<!-- Create AddScanResults entries. The syntax is:
AddScanResult, ipaddr, 'scanner_id', vuln_id, port, protocol, 'name', 'description', cve_ids, bugtraq_ids
where
  vuln_id: Valid RNA vulnerability IDs, or mapped third-party vulnerability IDs.
  proto: tcp|udp
!-->
<xsl:template match="result">
AddScanResult,<xsl:value-of select="host"/>,"OpenVAS",<xsl:value-of select="nvt/@oid"/>,<xsl:call-template name="portport" select="port"/>,<xsl:call-template name="portproto" select="port"/>,"<xsl:value-of select="nvt/name"/>","<xsl:value-of select="translate(description, '&quot;', &quot;'&quot;)"/>","cve_ids: <xsl:value-of select="translate(nvt/cve, ',', '')"/>","bugtraq_ids: <xsl:call-template name="bids" select="description"/>"</xsl:template>

<!-- MATCH HOST_START -->
<xsl:template match="host_start">
</xsl:template>

<!-- MATCH HOST_END -->
<xsl:template match="host_end">
</xsl:template>

<!-- MATCH SCAN_START -->
<xsl:template match="scan_start">
</xsl:template>

<!-- MATCH SCAN_END -->
<xsl:template match="scan_end">
</xsl:template>

<!-- MATCH RESULT_COUNT -->
<xsl:template match="result_count">
</xsl:template>

<!-- MATCH PORTS -->
<xsl:template match="ports">
</xsl:template>

<!-- MATCH TASK -->
<xsl:template match="task">
</xsl:template>

<!-- MATCH SCAN_RUN_STATUS -->
<xsl:template match="scan_run_status">
</xsl:template>

<!-- MATCH FILTER -->
<xsl:template match="filters">
</xsl:template>

<!-- MATCH SORT -->
<xsl:template match="sort">
</xsl:template>

<!-- MATCH RESULTS -->
<xsl:template match="results">
  <xsl:apply-templates/>
</xsl:template>

<!-- MATCH REPORT -->
<xsl:template match="/report"># Sourcefire Host Input File
SetSource,OpenVAS
  <xsl:apply-templates/>
</xsl:template>

</xsl:stylesheet>
