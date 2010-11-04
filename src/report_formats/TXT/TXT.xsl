<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    extension-element-prefixes="str">
  <xsl:output method="text" encoding="string" indent="no"/>

<!--
OpenVAS Manager
$Id$
Description: Report stylesheet for TXT format.

Authors:
Felix Wolfsteller <felix.wolfsteller@greenbone.de>

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

  <!-- Print a character x times. -->
  <xsl:template name="print_char_x_times">
      <xsl:param name="char"/>
      <xsl:param name="times"/>
      <xsl:if test="$times &gt; 0">
        <xsl:value-of select="$char"/>
        <xsl:call-template name="print_char_x_times">
          <xsl:with-param name="char" select="$char"/>
          <xsl:with-param name="times" select="$times - 1"/>
        </xsl:call-template>
      </xsl:if>
  </xsl:template>

  <!-- A Chapter heading. -->
  <xsl:template name="chapter">
    <xsl:param name="name"/>
    <xsl:value-of select="$name"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="print_char_x_times">
      <xsl:with-param name="char">=</xsl:with-param>
      <xsl:with-param name="times" select="string-length($name)"/>
    </xsl:call-template>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- A Section heading. -->
  <xsl:template name="section">
    <xsl:param name="name"/>
    <xsl:value-of select="$name"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="print_char_x_times">
      <xsl:with-param name="char">*</xsl:with-param>
      <xsl:with-param name="times" select="string-length($name)"/>
    </xsl:call-template>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- A Subsection heading. -->
  <xsl:template name="subsection">
    <xsl:param name="name"/>
    <xsl:value-of select="$name"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="print_char_x_times">
      <xsl:with-param name="char">-</xsl:with-param>
      <xsl:with-param name="times" select="string-length($name)"/>
    </xsl:call-template>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Align text left, fill remaining space with spaces. -->
  <xsl:template name="text-align-left">
    <xsl:param name="width"/>
    <xsl:param name="content"/>
    <xsl:value-of select="$content"/>
    <xsl:call-template name="print_char_x_times">
      <xsl:with-param name="char" select="' '"/>
      <xsl:with-param name="times" select="$width - string-length($content)"/>
    </xsl:call-template>
  </xsl:template>

  <!-- Align text right, fill remaining space with spaces. -->
  <xsl:template name="text-align-right">
    <xsl:param name="width"/>
    <xsl:param name="content"/>
    <xsl:call-template name="print_char_x_times">
      <xsl:with-param name="char" select="' '"/>
      <xsl:with-param name="times" select="$width - string-length($content)"/>
    </xsl:call-template>
    <xsl:value-of select="$content"/>
  </xsl:template>

<xsl:template name="wrap">
  <xsl:param name="string"></xsl:param>

  <xsl:for-each select="str:tokenize($string, '&#10;')">
    <xsl:call-template name="wrap-line">
      <xsl:with-param name="string"><xsl:value-of select="."/></xsl:with-param>
    </xsl:call-template>
    <xsl:text>
</xsl:text>
  </xsl:for-each>
</xsl:template>

<!-- This is called within a PRE. -->
<xsl:template name="wrap-line">
  <xsl:param name="string"></xsl:param>

  <xsl:variable name="to-next-newline">
    <xsl:value-of select="substring-before($string, '&#10;')"/>
  </xsl:variable>

  <xsl:choose>
    <xsl:when test="string-length($string) = 0">
      <!-- The string is empty. -->
    </xsl:when>
    <xsl:when test="(string-length($to-next-newline) = 0) and (substring($string, 1, 1) != '&#10;')">
      <!-- A single line missing a newline, output up to the edge. -->
<xsl:value-of select="substring($string, 1, 80)"/>
      <xsl:if test="string-length($string) &gt; 80">!
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string"><xsl:value-of select="substring($string, 81, string-length($string))"/></xsl:with-param>
</xsl:call-template>
      </xsl:if>
    </xsl:when>
    <xsl:when test="(string-length($to-next-newline) + 1 &lt; string-length($string)) and (string-length($to-next-newline) &lt; 80)">
      <!-- There's a newline before the edge, so output the line. -->
<xsl:value-of select="substring($string, 1, string-length($to-next-newline) + 1)"/>
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string"><xsl:value-of select="substring($string, string-length($to-next-newline) + 2, string-length($string))"/></xsl:with-param>
</xsl:call-template>
    </xsl:when>
    <xsl:otherwise>
      <!-- Any newline comes after the edge, so output up to the edge. -->
<xsl:value-of select="substring($string, 1, 80)"/>
      <xsl:if test="string-length($string) &gt; 80">!
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string"><xsl:value-of select="substring($string, 81, string-length($string))"/></xsl:with-param>
</xsl:call-template>
      </xsl:if>
    </xsl:otherwise>
  </xsl:choose>

</xsl:template>

  <xsl:template match="scan_end">
    <tr><td>Scan ended:</td><td><xsl:apply-templates /></td></tr>
  </xsl:template>

  <xsl:template match="note">
    <xsl:text>Note:</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="wrap">
      <xsl:with-param name="string" select="text"/>
    </xsl:call-template>
    <xsl:text>Note last modified: </xsl:text>
    <xsl:value-of select="modification_time"/>
    <xsl:text>.</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <xsl:template match="override">
    <xsl:if test="/report/filters/apply_overrides/text()='1'">
      <xsl:text>Override from </xsl:text>
      <xsl:choose>
        <xsl:when test="string-length(threat) = 0">
          <xsl:text>Any</xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="threat"/>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:text> to </xsl:text>
      <xsl:value-of select="new_threat"/>
      <xsl:text>:</xsl:text>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="wrap">
        <xsl:with-param name="string" select="text"/>
      </xsl:call-template>
      <xsl:text>Override last modified: </xsl:text>
      <xsl:value-of select="modification_time"/>
      <xsl:text>.</xsl:text>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="newline"/>
    </xsl:if>
  </xsl:template>

  <!-- Template for single issue -->
  <xsl:template match="result" mode="issue">
    <xsl:call-template name="subsection">
      <xsl:with-param name="name">Issue</xsl:with-param>
    </xsl:call-template>

    <xsl:text>NVT:    </xsl:text>
    <!-- TODO wrap, 80 char limit -->
    <!--
        <xsl:variable name="max" select="80"/>
          <xsl:choose>
            <xsl:when test="string-length(nvt/name) &gt; $max">
              <xsl:value-of select="substring(nvt/name, 0, $max)"/>...
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="nvt/name"/>
            </xsl:otherwise>
          </xsl:choose>-->
    <xsl:value-of select="nvt/name"/>
    <xsl:call-template name="newline"/>

    <xsl:text>OID:    </xsl:text>
    <xsl:value-of select="nvt/@oid"/>
    <xsl:call-template name="newline"/>

    <xsl:text>Threat: </xsl:text>
    <xsl:value-of select="threat"/>
    <xsl:choose>
        <xsl:when test="original_threat">
          <xsl:choose>
            <xsl:when test="threat = original_threat">
              <xsl:if test="string-length(nvt/cvss_base) &gt; 0">
                 <xsl:value-of select="concat(' (CVSS: ',nvt/cvss_base, ')')"/>
              </xsl:if>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="concat(' (Overridden from ', original_threat,')')"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:when>
        <xsl:otherwise>
          <xsl:if test="string-length(nvt/cvss_base) &gt; 0">
             <xsl:value-of select="concat(' (CVSS: ', nvt/cvss_base,')')"/>
          </xsl:if>
        </xsl:otherwise>
      </xsl:choose>
    <xsl:call-template name="newline"/>

    <xsl:text>Port:   </xsl:text>
    <xsl:value-of select="port"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:text>Description: </xsl:text>
    <xsl:call-template name="newline"/>

    <xsl:call-template name="wrap">
      <xsl:with-param name="string" select="description"/>
    </xsl:call-template>
    <xsl:call-template name="newline"/>

    <xsl:apply-templates select="notes/note"/>
    <xsl:apply-templates select="overrides/override"/>

    <xsl:call-template name="newline"/>
  </xsl:template>

  <xsl:template match="report">
    <xsl:text>This document reports on the results of an automatic security scan.</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>The report first summarises the results found.</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>Then, for each host, the report describes every issue found.</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>Please consider the advice given in each description, in order to rectify</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>the issue.</xsl:text><xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:choose>
      <xsl:when test="filters/apply_overrides/text()='1'">
        <xsl:text>Overrides are on.  When a result has an override, this report uses the</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>threat of the override.</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>Overrides are off.  Even when a result has an override, this report uses</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>the actual threat of the result.</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="newline"/>

    <xsl:choose>
      <xsl:when test="/report/filters/notes = 0">
        <xsl:text>Notes are excluded from the report.</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>Notes are included in the report.</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:text>This report might not show details of all issues that were found.</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:if test="/report/filters/result_hosts_only = 1">
      <xsl:text>It only lists hosts that produced issues.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="string-length(/report/filters/phrase) &gt; 0">
      <xsl:text>It shows issues that contain the search phrase "</xsl:text>
      <xsl:value-of select="/report/filters/phrase"/>
      <xsl:text>".</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(/report/filters/text(), 'h') = false">
      <xsl:text>Issues with the threat level "High" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(/report/filters/text(), 'm') = false">
      <xsl:text>Issues with the threat level "Medium" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(/report/filters/text(), 'l') = false">
      <xsl:text>Issues with the threat level "Low" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(/report/filters/text(), 'g') = false">
      <xsl:text>Issues with the threat level "Log" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(/report/filters/text(), 'd') = false">
      <xsl:text>Issues with the threat level "Debug" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(/report/filters/text(), 'f') = false">
      <xsl:text>Issues with the threat level "False Positive" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:call-template name="newline"/>

    <xsl:variable name="last" select="/report/results/@start + count(/report/results/result) - 1"/>
    <xsl:choose>
      <xsl:when test="$last = 0">
        <xsl:text>This report contains 0 results.</xsl:text>
        <xsl:text>  Before the filtering described above</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>there were </xsl:text>
        <xsl:value-of select="/report/result_count/text()"/>
        <xsl:text> results.</xsl:text>
      </xsl:when>
      <xsl:when test="$last = /report/results/@start">
        <xsl:text>This report contains result </xsl:text>
        <xsl:value-of select="$last"/>
        <xsl:text> of the </xsl:text>
        <xsl:value-of select="/report/result_count/filtered"/>
        <xsl:text> results selected by the</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>filtering above.</xsl:text>
        <xsl:text>  Before filtering there were </xsl:text>
        <xsl:value-of select="/report/result_count/text()"/>
        <xsl:text> results.</xsl:text>
      </xsl:when>
      <xsl:when test="$last = /report/result_count/filtered">
        <xsl:text>This report contains all </xsl:text>
        <xsl:value-of select="/report/result_count/filtered"/>
        <xsl:text> results selected by the</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>filtering described above.</xsl:text>
        <xsl:text>  Before filtering there were </xsl:text>
        <xsl:value-of select="/report/result_count/text()"/>
        <xsl:text> results.</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>This report contains results </xsl:text>
        <xsl:value-of select="/report/results/@start"/>
        <xsl:text> to </xsl:text>
        <xsl:value-of select="$last"/>
        <xsl:text> of the </xsl:text>
        <xsl:value-of select="/report/result_count/filtered"/>
        <xsl:text> results selected by the</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>filtering described above.</xsl:text>
        <xsl:text>  Before filtering there were </xsl:text>
        <xsl:value-of select="/report/result_count/text()"/>
        <xsl:text> results.</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:text>Scan started: </xsl:text><xsl:value-of select="/report/scan_start"/><xsl:call-template name="newline"/>
    <xsl:text>Scan ended:   </xsl:text>
    <xsl:value-of select="/report/scan_end"/><xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:call-template name="section">
      <xsl:with-param name="name">Host Summary</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="newline"/>

    <!-- The Overview Table. -->
    <xsl:variable name="col1-width" select="15"/>
    <xsl:variable name="col2-width" select="string-length('High')"/>
    <xsl:variable name="col3-width" select="string-length('Medium')"/>
    <xsl:variable name="col4-width" select="string-length('Low')"/>
    <xsl:variable name="col5-width" select="string-length('Log')"/>
    <xsl:variable name="col6-width" select="string-length('False Positive')"/>

    <xsl:text>Host            High  Medium  Low  Log  False Positive</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="host_start" >
      <xsl:variable name="current_host" select="host/text()" />
      <xsl:call-template name="text-align-left">
        <xsl:with-param name="width" select="$col1-width"/>
        <xsl:with-param name="content" select="$current_host"/>
      </xsl:call-template>
      <xsl:call-template name="text-align-right">
        <xsl:with-param name="width" select="$col2-width +1 "/>
        <xsl:with-param name="content" select="count(../results/result[host/text() = $current_host][threat/text() = 'High'])"/>
      </xsl:call-template>
      <xsl:call-template name="text-align-right">
        <xsl:with-param name="width" select="$col3-width +2 "/>
        <xsl:with-param name="content" select="count(../results/result[host/text() = $current_host][threat/text() = 'Medium'])"/>
      </xsl:call-template>
      <xsl:call-template name="text-align-right">
        <xsl:with-param name="width" select="$col4-width +2 "/>
        <xsl:with-param name="content" select="count(../results/result[host/text() = $current_host][threat/text() = 'Low'])"/>
      </xsl:call-template>
      <xsl:call-template name="text-align-right">
        <xsl:with-param name="width" select="$col5-width +2 "/>
        <xsl:with-param name="content" select="count(../results/result[host/text() = $current_host][threat/text() = 'Log'])"/>
      </xsl:call-template>
      <xsl:call-template name="text-align-right">
        <xsl:with-param name="width" select="$col6-width +2 "/>
        <xsl:with-param name="content" select="count(../results/result[host/text() = $current_host][threat/text() = 'False Positive'])"/>
      </xsl:call-template>
      <xsl:call-template name="newline"/>
    </xsl:for-each>

    <xsl:call-template name="text-align-left">
      <xsl:with-param name="width" select="$col1-width "/>
      <xsl:with-param name="content" select="concat('Total: ', count(host_start))"/>
    </xsl:call-template>
    <xsl:call-template name="text-align-right">
      <xsl:with-param name="width" select="$col2-width +1 "/>
      <xsl:with-param name="content" select="count(results/result[threat/text() = 'High'])"/>
    </xsl:call-template>
    <xsl:call-template name="text-align-right">
      <xsl:with-param name="width" select="$col3-width +2 "/>
      <xsl:with-param name="content" select="count(results/result[threat/text() = 'Medium'])"/>
    </xsl:call-template>
    <xsl:call-template name="text-align-right">
      <xsl:with-param name="width" select="$col4-width +2 "/>
      <xsl:with-param name="content" select="count(results/result[threat/text() = 'Low'])"/>
    </xsl:call-template>
    <xsl:call-template name="text-align-right">
      <xsl:with-param name="width" select="$col5-width +2 "/>
      <xsl:with-param name="content" select="count(results/result[threat/text() = 'Log'])"/>
    </xsl:call-template>
    <xsl:call-template name="text-align-right">
      <xsl:with-param name="width" select="$col6-width +2 "/>
      <xsl:with-param name="content" select="count(results/result[threat/text() = 'False Positive'])"/>
    </xsl:call-template>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:call-template name="chapter">
      <xsl:with-param name="name">II Results per Host</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="newline"/>

    <xsl:for-each select="host_start" >
      <xsl:variable name="current_host" select="host/text()" />
      <xsl:call-template name="section">
        <xsl:with-param name="name" select="concat('Host ', $current_host)"/>
      </xsl:call-template>
      <xsl:call-template name="newline"/>

      <xsl:text>Scanning of this host started at: </xsl:text>
      <xsl:value-of select="text()"/>
      <xsl:call-template name="newline"/>
      <xsl:text>Number of results: </xsl:text>
      <xsl:value-of select="count(../results/result[host/text()=$current_host])"/>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="newline"/>

      <xsl:call-template name="subsection">
        <xsl:with-param name="name">Port Summary for Host <xsl:value-of select="$current_host" /></xsl:with-param>
      </xsl:call-template>
      <xsl:call-template name="newline"/>

      <xsl:variable name="t2-col1-width" select="24"/>
      <xsl:call-template name="text-align-left">
        <xsl:with-param name="width" select="$t2-col1-width"/>
        <xsl:with-param name="content">Service (Port)</xsl:with-param>
      </xsl:call-template>
      <xsl:text>Threat Level</xsl:text>
      <xsl:call-template name="newline"/>

      <xsl:for-each select="../ports/port">
        <xsl:call-template name="text-align-left">
          <xsl:with-param name="width" select="$t2-col1-width"/>
          <xsl:with-param name="content" select="text()"/>
        </xsl:call-template>
        <xsl:value-of select="threat"/>
        <xsl:call-template name="newline"/>
      </xsl:for-each>
      <xsl:call-template name="newline"/>

      <xsl:call-template name="subsection">
        <xsl:with-param name="name">Security Issues for Host <xsl:value-of select="$current_host" /></xsl:with-param>
      </xsl:call-template>
      <xsl:call-template name="newline"/>

      <xsl:apply-templates select="../results/result[host/text()=$current_host]" mode="issue"/>
    </xsl:for-each>
  </xsl:template>

  <!-- Math the root (report) -->
  <xsl:template match="/">
    <xsl:call-template name="chapter">
      <xsl:with-param name="name">I Summary</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="newline"/>
    <xsl:apply-templates/>
  </xsl:template>

</xsl:stylesheet>
