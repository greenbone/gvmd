<?xml version="1.0"?>
<!--
Copyright (C) 2010-2019 Greenbone Networks GmbH

SPDX-License-Identifier: GPL-2.0-or-later

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
-->

<!-- CSV Results Export Stylesheet -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:func="http://exslt.org/functions"
                xmlns:gvm="http://greenbone.net"
                xmlns:str="http://exslt.org/strings"
                extension-element-prefixes="func str">
<xsl:output method="text"
            encoding="string"/>

<func:function name="gvm:report">
  <xsl:choose>
    <xsl:when test="count(/report/report) &gt; 0">
      <func:result select="/report/report"/>
    </xsl:when>
    <xsl:otherwise>
      <func:result select="/report"/>
    </xsl:otherwise>
  </xsl:choose>
</func:function>

<!--
  Add a single quote to strings that could otherwise be interpreted as
  formulas in common spreadsheet software.
-->
<func:function name="gvm:formula_quote">
  <xsl:param name="string" select="''"/>
  <xsl:choose>
    <xsl:when test="string(number($string)) != 'NaN'">
      <func:result select="$string"/>
    </xsl:when>
    <xsl:when test="starts-with ($string, '=') or starts-with ($string, '@') or starts-with ($string, '+') or starts-with ($string, '-')">
      <xsl:variable name="apostrophe">&apos;</xsl:variable>
      <func:result select="concat ($apostrophe, $string)"/>
    </xsl:when>
    <xsl:otherwise>
      <func:result select="$string"/>
    </xsl:otherwise>
  </xsl:choose>
</func:function>

<xsl:template name="newline">
  <xsl:text>
</xsl:text>
</xsl:template>

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

<xsl:template name="nvt_name">
  <xsl:variable name="name_without_single_quotes"
                select="translate(nvt/name, &quot;&apos;&quot;, '')" />
  <xsl:value-of select="gvm:formula_quote (str:replace ($name_without_single_quotes, $quote, $two-quotes))"/>
</xsl:template>

<func:function name="gvm:get-nvt-tag">
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

<xsl:param name="quote">"</xsl:param>
<xsl:param name="two-quotes">""</xsl:param>

<!-- MATCH RESULT -->
<xsl:template match="result">
  <xsl:variable name="ip" select="host/text()"/>
  <xsl:variable name="summary-tag" select="gvm:get-nvt-tag (nvt/tags, 'summary')"/>
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
  <xsl:variable name="port">
    <xsl:call-template name="portport" select="port"/>
  </xsl:variable>

  <xsl:value-of select="gvm:formula_quote ($ip)"/>
  <xsl:text>,</xsl:text>
  <xsl:value-of select="gvm:formula_quote (../../host[ip = $ip]/detail[name = 'hostname']/value)"/>
  <xsl:text>,</xsl:text>
  <xsl:value-of select="gvm:formula_quote ($port)"/>
  <xsl:text>,</xsl:text>
  <xsl:choose>
    <xsl:when test="string-length ($port) &gt; 0">
      <xsl:call-template name="portproto" select="gvm:formula_quote (port)"/>
    </xsl:when>
  </xsl:choose>
  <xsl:text>,</xsl:text>
  <xsl:value-of select="gvm:formula_quote (severity)"/>
  <xsl:text>,</xsl:text>
  <xsl:value-of select="gvm:formula_quote (threat)"/>
  <xsl:text>,"</xsl:text>
  <xsl:if test="gvm:get-nvt-tag (nvt/tags, 'solution_type') != ''">
    <xsl:value-of select="gvm:formula_quote (str:replace (gvm:get-nvt-tag (nvt/tags, 'solution_type'), $quote, $two-quotes))"/>
  </xsl:if>
  <xsl:text>","</xsl:text>
  <xsl:call-template name="nvt_name"/>
  <xsl:text>","</xsl:text>
  <xsl:value-of select="gvm:formula_quote (str:replace ($summary, $quote, $two-quotes))"/>
  <xsl:text>","</xsl:text>
  <xsl:choose>
    <xsl:when test="string-length (description) &lt; 2">
      <xsl:text>Vulnerability was detected according to the Vulnerability Detection Method.</xsl:text>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="gvm:formula_quote (str:replace (description, $quote, $two-quotes))"/>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:text>",</xsl:text>
  <xsl:value-of select="gvm:formula_quote (nvt/@oid)"/>

  <xsl:text>,"</xsl:text> <!-- column "CVEs" -->

  <xsl:variable name="cell_cves">
    <xsl:for-each select="nvt/refs/ref[@type = 'cve']">
      <xsl:value-of select="str:replace (@id, $quote, $two-quotes)"/>
      <xsl:text>,</xsl:text>
    </xsl:for-each>
  </xsl:variable>
  <xsl:value-of select="gvm:formula_quote (substring ($cell_cves, 0, string-length($cell_cves)))"/>

  <xsl:text>",</xsl:text>

  <xsl:value-of select="gvm:formula_quote (../../task/@id)"/>
  <xsl:text>,"</xsl:text>
  <xsl:value-of select="gvm:formula_quote (str:replace (../../task/name, $quote, $two-quotes))"/>
  <xsl:text>",</xsl:text>
  <xsl:value-of select="gvm:formula_quote (../../host[ip = $ip]/start)"/>
  <xsl:text>,</xsl:text>
  <xsl:value-of select="gvm:formula_quote (@id)"/>
  <xsl:text>,"</xsl:text>
  <xsl:if test="gvm:get-nvt-tag (nvt/tags, 'impact') != 'N/A'">
    <xsl:value-of select="gvm:formula_quote (str:replace (gvm:get-nvt-tag (nvt/tags, 'impact'), $quote, $two-quotes))"/>
  </xsl:if>
  <xsl:text>","</xsl:text>
  <xsl:if test="gvm:get-nvt-tag (nvt/tags, 'solution') != 'N/A'">
    <xsl:value-of select="gvm:formula_quote (str:replace (gvm:get-nvt-tag (nvt/tags, 'solution'), $quote, $two-quotes))"/>
  </xsl:if>
  <xsl:text>","</xsl:text>
  <xsl:if test="gvm:get-nvt-tag (nvt/tags, 'affected') != 'N/A'">
    <xsl:value-of select="gvm:formula_quote (str:replace (gvm:get-nvt-tag (nvt/tags, 'affected'), $quote, $two-quotes))"/>
  </xsl:if>
  <xsl:text>","</xsl:text>
  <xsl:if test="gvm:get-nvt-tag (nvt/tags, 'insight') != 'N/A'">
    <xsl:value-of select="gvm:formula_quote (str:replace (gvm:get-nvt-tag (nvt/tags, 'insight'), $quote, $two-quotes))"/>
  </xsl:if>
  <xsl:text>","</xsl:text>
  <xsl:if test="gvm:get-nvt-tag (nvt/tags, 'vuldetect') != 'N/A'">
    <xsl:value-of select="gvm:formula_quote (str:replace (gvm:get-nvt-tag (nvt/tags, 'vuldetect'), $quote, $two-quotes))"/>
    <xsl:call-template name="newline"/>
    <xsl:text>Details:</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:choose>
      <xsl:when test="nvt/@oid = 0">
        <xsl:if test="delta/text()">
          <xsl:call-template name="newline"/>
        </xsl:if>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="max" select="77"/>
        <xsl:choose>
          <xsl:when test="string-length(nvt/name) &gt; $max">
            <xsl:value-of select="gvm:formula_quote (str:replace (substring (nvt/name, 0, $max), $quote, $two-quotes))"/>
            <xsl:text>...</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="gvm:formula_quote (str:replace (nvt/name, $quote, $two-quotes))"/>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:call-template name="newline"/>
        <xsl:text>(OID: </xsl:text>
        <xsl:value-of select="nvt/@oid"/>
        <xsl:text>)</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:if test="scan_nvt_version != ''">
      <xsl:text>Version used: </xsl:text>
      <xsl:value-of select="str:replace (scan_nvt_version, $quote, $two-quotes)"/>
      <xsl:call-template name="newline"/>
    </xsl:if>
  </xsl:if>
  <xsl:text>","</xsl:text>
  <xsl:if test="count (detection)">
    <xsl:text>Product: </xsl:text>
    <xsl:value-of select="str:replace (detection/result/details/detail[name = 'product']/value/text(), $quote, $two-quotes)"/>
    <xsl:call-template name="newline"/>
    <xsl:text>Method: </xsl:text>
    <xsl:value-of select="str:replace (detection/result/details/detail[name = 'source_name']/value/text(), $quote, $two-quotes)"/>
    <xsl:call-template name="newline"/>
    <xsl:text>(OID: </xsl:text>
    <xsl:value-of select="detection/result/details/detail[name = 'source_oid']/value/text()"/>
    <xsl:text>)</xsl:text>
    <xsl:call-template name="newline"/>
  </xsl:if>

  <xsl:text>","</xsl:text> <!-- column "BIDs" -->

  <xsl:variable name="cell_bids">
    <xsl:for-each select="nvt/refs/ref[@type = 'bid']">
      <xsl:value-of select="str:replace (@id, $quote, $two-quotes)"/>
      <xsl:text>,</xsl:text>
    </xsl:for-each>
  </xsl:variable>
  <xsl:value-of select="gvm:formula_quote (substring ($cell_bids, 0, string-length($cell_bids)))"/>

  <xsl:text>","</xsl:text> <!-- column "CERTs" -->

  <xsl:variable name="cell_certs">
    <xsl:for-each select="nvt/refs/ref[@type = 'dfn-cert']">
      <xsl:value-of select="@id"/>
      <xsl:text>,</xsl:text>
    </xsl:for-each>
    <xsl:for-each select="nvt/refs/ref[@type = 'cert-bund']">
      <xsl:value-of select="str:replace (@id, $quote, $two-quotes)"/>
      <xsl:text>,</xsl:text>
    </xsl:for-each>
  </xsl:variable>
  <xsl:value-of select="gvm:formula_quote (substring ($cell_certs, 0, string-length($cell_certs)))"/>

  <xsl:text>","</xsl:text> <!-- column "Other References" -->

  <xsl:variable name="cell_urls">
    <xsl:for-each select="nvt/refs/ref[@type = 'URL']">
      <xsl:value-of select="str:replace (@id, $quote, $two-quotes)"/>
      <xsl:text>,</xsl:text>
    </xsl:for-each>
  </xsl:variable>
  <xsl:value-of select="gvm:formula_quote (substring ($cell_urls, 0, string-length($cell_urls)))"/>

  <xsl:text>"</xsl:text>
  <xsl:text>
</xsl:text>
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
  <xsl:text>IP,Hostname,Port,Port Protocol,CVSS,Severity,Solution Type,NVT Name,Summary,Specific Result,NVT OID,CVEs,Task ID,Task Name,Timestamp,Result ID,Impact,Solution,Affected Software/OS,Vulnerability Insight,Vulnerability Detection Method,Product Detection Result,BIDs,CERTs,Other References
</xsl:text>
  <xsl:apply-templates select="results"/>
</xsl:template>

</xsl:stylesheet>
