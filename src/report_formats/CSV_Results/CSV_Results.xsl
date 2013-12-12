<?xml version="1.0"?>
<!--
$Id$
Description: CSV Results Export Stylesheet

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

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:func="http://exslt.org/functions"
                xmlns:openvas="http://openvas.org"
                xmlns:str="http://exslt.org/strings"
                extension-element-prefixes="func str">
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
  <xsl:variable name="port">
    <xsl:choose>
      <xsl:when test="string-length($port_nr) > 0">
        <xsl:value-of select="$port_nr"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$before_slash"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>
  <xsl:choose>
    <xsl:when test="$port = 'general'" />
    <xsl:otherwise>
      <xsl:value-of select="$port"/>
    </xsl:otherwise>
  </xsl:choose>
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
  <xsl:variable name="proto">
    <xsl:choose>
      <xsl:when test="string-length($port_proto) > 0">
        <xsl:value-of select="$port_proto"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$after_slash"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>
  <xsl:choose>
    <xsl:when test="$proto = 'tcp'">
      <xsl:value-of select="$proto"/>
    </xsl:when>
    <xsl:when test="$proto = 'udp'">
      <xsl:value-of select="$proto"/>
    </xsl:when>
    <xsl:otherwise />
  </xsl:choose>
</xsl:template>

<!-- Ensure NOCVE is removed -->
<xsl:template name="cve">
  <xsl:variable name="cve_list" select="translate(nvt/cve, ',', '')" />
  <xsl:choose>
    <xsl:when test="$cve_list = 'NOCVE'"/>
    <xsl:otherwise>
      <xsl:value-of select="$cve_list"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- Ensure NOBID is removed -->
<xsl:template name="bid">
  <xsl:variable name="bid_list" select="translate(nvt/bid, ',', '')" />
  <xsl:choose>
    <xsl:when test="$bid_list = 'NOBID'"/>
    <xsl:otherwise>
      <xsl:value-of select="$bid_list"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- Substitute "Open Port" if the NVT name is empty -->
<xsl:template name="nvt_name">
  <xsl:variable name="name_without_quotes" select="translate(nvt/name, &quot;&apos;&quot;, '')" />
  <xsl:choose>
    <xsl:when test="string-length($name_without_quotes) > 0">
      <xsl:value-of select="$name_without_quotes"/>
    </xsl:when>
    <xsl:otherwise>Open Port</xsl:otherwise>
  </xsl:choose>
</xsl:template>

<func:function name="openvas:get-nvt-tag">
  <xsl:param name="tags"/>
  <xsl:param name="name"/>
  <xsl:variable name="after">
    <xsl:value-of select="substring-after (nvt/tags, concat ($name, '='))"/>
  </xsl:variable>
  <xsl:choose>
      <xsl:when test="contains ($after, '|')">
        <func:result select="substring-before ($after, '|')"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="$after"/>
      </xsl:otherwise>
  </xsl:choose>
</func:function>

<func:function name="openvas:new-style-nvt">
  <xsl:param name="nvt"/>
  <xsl:choose>
    <xsl:when test="string-length (openvas:get-nvt-tag ($nvt/tags, 'summary'))
                    and string-length (openvas:get-nvt-tag ($nvt/tags, 'affected'))
                    and string-length (openvas:get-nvt-tag ($nvt/tags, 'insight'))
                    and string-length (openvas:get-nvt-tag ($nvt/tags, 'vuldetect'))
                    and string-length (openvas:get-nvt-tag ($nvt/tags, 'impact'))
                    and string-length (openvas:get-nvt-tag ($nvt/tags, 'solution'))">
      <func:result select="1"/>
    </xsl:when>
    <xsl:otherwise>
      <func:result select="0"/>
    </xsl:otherwise>
  </xsl:choose>
</func:function>

<xsl:param name="quote">"</xsl:param>
<xsl:param name="two-quotes">""</xsl:param>

<!-- MATCH RESULT -->
<xsl:template match="result">
  <xsl:variable name="ip" select="host"/>
  <xsl:variable name="summary-tag" select="openvas:get-nvt-tag (nvt/tags, 'summary')"/>
  <xsl:variable name="summary">
    <xsl:choose>
      <xsl:when test="string-length ($summary-tag) &gt; 0">
        <xsl:value-of select="$summary-tag"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="description"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <xsl:value-of select="$ip"/>
  <xsl:text>,</xsl:text>
  <xsl:value-of select="../../host[ip = $ip]/detail[name = 'hostname']/value"/>
  <xsl:text>,</xsl:text>
  <xsl:call-template name="portport" select="port"/>
  <xsl:text>,</xsl:text>
  <xsl:call-template name="portproto" select="port"/>
  <xsl:text>,</xsl:text>
  <xsl:value-of select="nvt/cvss_base"/>
  <xsl:text>,</xsl:text>
  <xsl:value-of select="threat"/>
  <xsl:text>,"</xsl:text>
  <xsl:if test="openvas:new-style-nvt (nvt)">
    <xsl:choose>
      <xsl:when test="string-length (description) &lt; 2">
        <xsl:text>Vulnerability was detected according to the Vulnerability Detection Method.</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="str:replace (description, $quote, $two-quotes)"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:if>
  <xsl:text>","</xsl:text>
  <xsl:value-of select="str:replace ($summary, $quote, $two-quotes)"/>
  <xsl:text>",</xsl:text>
  <xsl:value-of select="nvt/@oid"/>
  <xsl:text>,"</xsl:text>
  <xsl:call-template name="nvt_name"/>
  <xsl:text>","</xsl:text>
  <xsl:value-of select="nvt/cve"/>
  <xsl:text>",</xsl:text>
  <xsl:value-of select="../../task/@id"/>
  <xsl:text>,"</xsl:text>
  <xsl:value-of select="str:replace (../../task/name, $quote, $two-quotes)"/>
  <xsl:text>",</xsl:text>
  <xsl:value-of select="../../host[ip = $ip]/start"/>
  <xsl:text>,</xsl:text>
  <xsl:value-of select="@id"/>
  <xsl:text>
</xsl:text>
</xsl:template>

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
<xsl:template match="/report">
  <xsl:text>Host IP, Host Name, Port, Port Protocol, CVSS, Severity, Detection Result, Summary, OID, NVT Name, CVEs, Task ID, Task Name, Timestamp, Result ID
</xsl:text>
  <xsl:apply-templates select="results"/>
</xsl:template>

</xsl:stylesheet>
