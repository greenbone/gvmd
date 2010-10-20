<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    extension-element-prefixes="str">
  <xsl:output method="html"
              doctype-system="http://www.w3.org/TR/html4/strict.dtd"
              doctype-public="-//W3C//DTD HTML 4.01//EN"
              encoding="UTF-8" />

<!--
OpenVAS Manager
$Id$
Description: Report stylesheet for HTML format.

Authors:
Matthew Mundell <matthew.mundell@greenbone.de>

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

  <!-- <xsl:key name="host_results" match="*/result" use="host" /> -->
  <!-- <xsl:key name="host_ports" match="*/result[port]" use="../host" /> -->

<!-- This is called within a PRE. -->
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
<xsl:value-of select="substring($string, 1, 90)"/>
      <xsl:if test="string-length($string) &gt; 90">&#8629;
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string"><xsl:value-of select="substring($string, 91, string-length($string))"/></xsl:with-param>
</xsl:call-template>
      </xsl:if>
    </xsl:when>
    <xsl:when test="(string-length($to-next-newline) + 1 &lt; string-length($string)) and (string-length($to-next-newline) &lt; 90)">
      <!-- There's a newline before the edge, so output the line. -->
<xsl:value-of select="substring($string, 1, string-length($to-next-newline) + 1)"/>
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string"><xsl:value-of select="substring($string, string-length($to-next-newline) + 2, string-length($string))"/></xsl:with-param>
</xsl:call-template>
    </xsl:when>
    <xsl:otherwise>
      <!-- Any newline comes after the edge, so output up to the edge. -->
<xsl:value-of select="substring($string, 1, 90)"/>
      <xsl:if test="string-length($string) &gt; 90">&#8629;
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string"><xsl:value-of select="substring($string, 91, string-length($string))"/></xsl:with-param>
</xsl:call-template>
      </xsl:if>
    </xsl:otherwise>
  </xsl:choose>

</xsl:template>

  <xsl:template match="scan_start">
    <tr><td>Scan started:</td><td><xsl:apply-templates /></td></tr>
  </xsl:template>

  <xsl:template match="scan_end">
    <tr><td>Scan ended:</td><td><xsl:apply-templates /></td></tr>
  </xsl:template>

  <xsl:template match="note">
    <div style="padding:4px; margin:3px; margin-bottom:0px; margin-top:0px; border: 1px solid #CCCCCC; border-top: 0px; background-color: #ffff90;">
      <b>Note</b>
      <pre>
        <xsl:call-template name="wrap">
          <xsl:with-param name="string"><xsl:value-of select="text"/></xsl:with-param>
        </xsl:call-template>
      </pre>
      Last modified: <xsl:value-of select="modification_time"/>.
    </div>
  </xsl:template>

  <xsl:template match="override">
    <xsl:if test="/report/filters/apply_overrides/text()='1'">
      <div style="padding:4px; margin:3px; margin-bottom:0px; margin-top:0px; border: 1px solid #CCCCCC; border-top: 0px; background-color: #ffff90;">
        <b>
          Override from
          <xsl:choose>
            <xsl:when test="string-length(threat) = 0">
              Any
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="threat"/>
            </xsl:otherwise>
          </xsl:choose>
          to <xsl:value-of select="new_threat"/></b><br/>
        <pre>
          <xsl:call-template name="wrap">
            <xsl:with-param name="string"><xsl:value-of select="text"/></xsl:with-param>
          </xsl:call-template>
        </pre>
        Last modified: <xsl:value-of select="modification_time"/>.
      </div>
    </xsl:if>
  </xsl:template>

  <xsl:template match="result" mode="issue">

    <xsl:variable name="style">
      <xsl:choose>
         <xsl:when test="threat='Low'">background:#539dcb</xsl:when>
         <xsl:when test="threat='Medium'">background:#f99f31</xsl:when>
         <xsl:when test="threat='High'">background:#cb1d17</xsl:when>
         <xsl:otherwise>background:#d5d5d5</xsl:otherwise>
      </xsl:choose>
    </xsl:variable>

    <div style="{$style}; padding:4px; margin:3px; margin-bottom:0px; color: #FFFFFF; border: 1px solid #CCCCCC; border-bottom: 0px;">
      <div style="float:right; text-align:right">
        <xsl:value-of select="port"/>
      </div>
      <b><xsl:value-of select="threat"/></b>
      <xsl:choose>
        <xsl:when test="original_threat">
          <xsl:choose>
            <xsl:when test="threat = original_threat">
              <xsl:if test="string-length(nvt/cvss_base) &gt; 0">
                 (CVSS: <xsl:value-of select="nvt/cvss_base"/>)
              </xsl:if>
            </xsl:when>
            <xsl:otherwise>
              (Overridden from <b><xsl:value-of select="original_threat"/></b>)
            </xsl:otherwise>
          </xsl:choose>
        </xsl:when>
        <xsl:otherwise>
          <xsl:if test="string-length(nvt/cvss_base) &gt; 0">
             (CVSS: <xsl:value-of select="nvt/cvss_base"/>)
          </xsl:if>
        </xsl:otherwise>
      </xsl:choose>
      <div style="width: 100%">
        NVT:
        <xsl:variable name="max" select="80"/>
          <xsl:choose>
            <xsl:when test="string-length(nvt/name) &gt; $max">
              <xsl:value-of select="substring(nvt/name, 0, $max)"/>...
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="nvt/name"/>
            </xsl:otherwise>
          </xsl:choose>
        (OID: <xsl:value-of select="nvt/@oid"/>)
      </div>
    </div>
    <div style="padding:4px; margin:3px; margin-bottom:0px; margin-top:0px; border: 1px solid #CCCCCC; border-top: 0px;">
      <pre>
        <xsl:call-template name="wrap">
          <xsl:with-param name="string"><xsl:apply-templates select="description"/></xsl:with-param>
        </xsl:call-template>
      </pre>
    </div>
    <xsl:apply-templates select="notes/note"/>
    <xsl:apply-templates select="overrides/override"/>

  </xsl:template>

  <xsl:template match="report">
    <h1>Summary</h1>

    <p>
      This document reports on the results of an automatic security scan.
      The report first summarises the results found.  Then, for each host,
      the report describes every issue found.  Please consider the
      advice given in each description, in order to rectify the issue.
    </p>

    <p>
      <xsl:choose>
        <xsl:when test="filters/apply_overrides/text()='1'">
          Overrides are on.  When a result has an override, this report uses the threat of the override.
        </xsl:when>
        <xsl:otherwise>
          Overrides are off.  Even when a result has an override, this report uses the actual threat of the result.
        </xsl:otherwise>
      </xsl:choose>
    </p>

    <p>
      <xsl:choose>
        <xsl:when test="/report/filters/notes = 0">
          Notes are excluded from the report.
        </xsl:when>
        <xsl:otherwise>
          Notes are included in the report.
        </xsl:otherwise>
      </xsl:choose>
    </p>

    <p>
      This report might not show details of all issues that were found.
      <xsl:if test="filters/result_hosts_only = 1">
        It only lists hosts that produced issues.
      </xsl:if>
      <xsl:if test="string-length(filters/phrase) &gt; 0">
        It shows issues that contain the search phrase "<xsl:value-of select="filters/phrase"/>".
      </xsl:if>
      <xsl:if test="contains(filters/text(), 'h') = false">
        Issues with the threat level "High" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/text(), 'm') = false">
        Issues with the threat level "Medium" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/text(), 'l') = false">
        Issues with the threat level "Low" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/text(), 'g') = false">
        Issues with the threat level "Log" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/text(), 'd') = false">
        Issues with the threat level "Debug" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/text(), 'f') = false">
        Issues with the threat level "False Positive" are not shown.
      </xsl:if>
    </p>

    <table>
      <xsl:apply-templates select="scan_start" />
      <xsl:apply-templates select="scan_end" />
    </table>

    <h2>Host Summary</h2>

    <table>
      <tr style="background-color: #d5d5d5;">
        <td>Host</td>
        <td>High</td>
        <td>Medium</td>
        <td>Low</td>
        <td>Log</td>
        <td>False Positive</td>
      </tr>
      <xsl:for-each select="host_start" >
        <xsl:variable name="current_host" select="host/text()" />
        <tr>
          <td>
            <a href="#{$current_host}"><xsl:value-of select="$current_host"/></a>
          </td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'High'])"/></td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'Medium'])"/></td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'Low'])"/></td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'Log'])"/></td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'False Positive'])"/></td>
        </tr>
      </xsl:for-each>
      <tr>
        <td>Total: <xsl:value-of select="count(host_start)"/></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'High'])"/></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'Medium'])"/></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'Low'])"/></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'Log'])"/></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'False Positive'])"/></td>
      </tr>
    </table>

    <h1>Results per Host</h1>

    <xsl:for-each select="host_start" >
      <xsl:variable name="current_host" select="host/text()" />

      <h2 id="{$current_host}">Host <xsl:value-of select="host/text()"/></h2>
      <table>
        <tr>
          <td>Scanning of this host started at:</td>
          <td><xsl:value-of select="text()"/></td>
        </tr>
        <tr>
          <td>Number of results:</td>
          <td>
            <xsl:value-of select="count(../results/result[host/text()=$current_host])"/>
          </td>
        </tr>
      <!-- Number of results: <xsl:value-of select="count(key('host_results', $current_host))"/> -->
      </table>

      <h3>Port Summary for Host <xsl:value-of select="$current_host" /></h3>

      <table>
        <tr style="background-color: #d5d5d5;">
          <td>Service (Port)</td>
          <td>Threat Level</td>
        </tr>

        <xsl:for-each select="../ports/port">
          <tr>
            <td><xsl:value-of select="text()"/></td>
            <td><xsl:value-of select="threat"/></td>
          </tr>
        </xsl:for-each>

      <!-- <xsl:apply-templates select="key('host_results', $current_host)" mode="FIX"/> -->

      </table>

      <h3>Security Issues for Host <xsl:value-of select="$current_host" /></h3>

      <xsl:apply-templates select="../results/result[host/text()=$current_host]" mode="issue"/>

    </xsl:for-each>

  </xsl:template>

  <xsl:template match="/">
    <html>
      <head>
        <link rel="stylesheet" type="text/css" href="./style.css" />
        <title>Scan Report</title>
      </head>
      <body style="background-color: #FFFFFF; margin: 0px; font: small Verdana, sans-serif; font-size: 12px; color: #1A1A1A;">
        <div style="width: 98%; width:700px; align: center; margin-left: auto; margin-right: auto;">
          <table style="width: 100%;" cellpadding="3" cellspacing="0">
            <tr>
              <td valign="top">
                <xsl:apply-templates/>
                <div style="text-align: center;">
                  This file was automatically generated.
                </div>
              </td>
            </tr>
          </table>
        </div>
      </body>
    </html>
  </xsl:template>

</xsl:stylesheet>
