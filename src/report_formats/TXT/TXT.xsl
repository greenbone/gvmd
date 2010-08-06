<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:set="http://exslt.org/sets">
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

  <!-- Mainly the overviews. -->
  <xsl:template match="report">
    <xsl:text>This document reports on the results of an automatic security scan.</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>The report first summarises the results found.</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>Then, for each host, the report describes every issue found.</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>Please consider the advice given in each description, in order to rectify</xsl:text><xsl:call-template name="newline"/>
    <xsl:text>the issue.</xsl:text><xsl:call-template name="newline"/>

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

      <xsl:for-each select="set:distinct(../results/result/port)">
        <xsl:call-template name="text-align-left">
          <xsl:with-param name="width" select="$t2-col1-width"/>
          <xsl:with-param name="content" select="."/>
        </xsl:call-template>
        <xsl:value-of select="../threat"/>
        <xsl:call-template name="newline"/>
      </xsl:for-each>

      <!--
      <h3>Security Issues for Host <xsl:value-of select="$current_host" /></h3>
      <xsl:apply-templates select="../results/result[host/text()=$current_host]" mode="issue"/>-->
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
