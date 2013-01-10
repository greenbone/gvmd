<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:date="http://exslt.org/dates-and-times"
    extension-element-prefixes="str date">
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
  <xsl:param name="string"/>

  <xsl:for-each select="str:tokenize($string, '&#10;')">
    <xsl:call-template name="wrap-line">
      <xsl:with-param name="string" select="."/>
    </xsl:call-template>
    <xsl:text>
</xsl:text>
  </xsl:for-each>
</xsl:template>

<!-- Split long comma-separated lists into several lines of items_per_line
     elements without cutting in the middle of an item. -->
<xsl:template name="wrapped_list">
  <xsl:param name="list"/>
  <xsl:param name="items_per_line"/>

  <xsl:for-each select="str:tokenize($list, ',')">
    <xsl:choose>
      <xsl:when test="position() mod $items_per_line = 1">
        <xsl:choose>
          <xsl:when test="position() = 1">
            <xsl:value-of select="normalize-space(.)"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>
       </xsl:text><xsl:value-of select="normalize-space(.)"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="concat(',', normalize-space(.))"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
</xsl:template>

<xsl:template match="nvt">
  <xsl:variable name="cve_ref">
    <xsl:if test="cve != '' and cve != 'NOCVE'">
      <xsl:value-of select="cve/text()"/>
    </xsl:if>
  </xsl:variable>
  <xsl:variable name="bid_ref">
    <xsl:if test="bid != '' and bid != 'NOBID'">
      <xsl:value-of select="bid/text()"/>
    </xsl:if>
  </xsl:variable>
  <xsl:variable name="xref_ref">
    <xsl:if test="xref != '' and xref != 'NOXREF'">
      <xsl:value-of select="xref/text()"/>
    </xsl:if>
  </xsl:variable>

  <xsl:if test="$cve_ref != '' or $bid_ref != '' or $xref_ref != ''">
    <xsl:text>References:</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:if test="$cve_ref != ''">
      <xsl:text>  </xsl:text>
      <xsl:text>CVE: </xsl:text>
      <xsl:call-template name="wrapped_list">
        <xsl:with-param name="list" select="$cve_ref"/>
        <xsl:with-param name="items_per_line" select="5"/>
      </xsl:call-template>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="$bid_ref != ''">
      <xsl:text>  </xsl:text>
      <xsl:text>BID: </xsl:text>
      <xsl:call-template name="wrapped_list">
        <xsl:with-param name="list" select="$bid_ref"/>
        <xsl:with-param name="items_per_line" select="10"/>
      </xsl:call-template>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="$xref_ref != ''">
      <xsl:text>  </xsl:text>
      <xsl:text>Other: </xsl:text>
      <xsl:for-each select="str:split($xref_ref, ',')">
        <xsl:call-template name="newline"/>
        <xsl:text>    </xsl:text>
        <xsl:value-of select="."/>
      </xsl:for-each>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:call-template name="newline"/>
  </xsl:if>
</xsl:template>

<!-- This is called within a PRE. -->
<xsl:template name="wrap-line">
  <xsl:param name="string"/>

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
  <xsl:with-param name="string" select="substring($string, 81, string-length($string))"/>
</xsl:call-template>
      </xsl:if>
    </xsl:when>
    <xsl:when test="(string-length($to-next-newline) + 1 &lt; string-length($string)) and (string-length($to-next-newline) &lt; 80)">
      <!-- There's a newline before the edge, so output the line. -->
<xsl:value-of select="substring($string, 1, string-length($to-next-newline) + 1)"/>
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string" select="substring($string, string-length($to-next-newline) + 2, string-length($string))"/>
</xsl:call-template>
    </xsl:when>
    <xsl:otherwise>
      <!-- Any newline comes after the edge, so output up to the edge. -->
<xsl:value-of select="substring($string, 1, 80)"/>
      <xsl:if test="string-length($string) &gt; 80">!
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string" select="substring($string, 81, string-length($string))"/>
</xsl:call-template>
      </xsl:if>
    </xsl:otherwise>
  </xsl:choose>

</xsl:template>

  <xsl:template name="scan_start">
    <xsl:param name="date" select="scan_start"/>
    <xsl:if test="string-length ($date)">
      <xsl:choose>
        <xsl:when test="contains($date, '+')">
          <xsl:value-of select="concat (date:day-abbreviation ($date), ' ', date:month-abbreviation ($date), ' ', date:day-in-month ($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ':', format-number(date:second-in-minute($date), '00'), ' ', date:year($date), ' ', substring-after ($date, '+'))"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="concat (date:day-abbreviation ($date), ' ', date:month-abbreviation ($date), ' ', date:day-in-month ($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ':', format-number(date:second-in-minute($date), '00'), ' ', date:year($date), ' UTC')"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:if>
  </xsl:template>

  <xsl:template name="scan_end">
    <xsl:param name="date" select="scan_end"/>
    <xsl:if test="string-length ($date)">
      <xsl:choose>
        <xsl:when test="contains($date, '+')">
          <xsl:value-of select="concat (date:day-abbreviation ($date), ' ', date:month-abbreviation ($date), ' ', date:day-in-month ($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ':', format-number(date:second-in-minute($date), '00'), ' ', date:year($date), ' ', substring-after ($date, '+'))"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="concat (date:day-abbreviation ($date), ' ', date:month-abbreviation ($date), ' ', date:day-in-month ($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ':', format-number(date:second-in-minute($date), '00'), ' ', date:year($date), ' UTC')"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:if>
  </xsl:template>

  <xsl:template match="note">
    <xsl:param name="delta">0</xsl:param>
    <xsl:text>Note</xsl:text>
    <xsl:if test="$delta and $delta &gt; 0"> (Result <xsl:value-of select="$delta"/>)</xsl:if>
    <xsl:text>:</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="wrap">
      <xsl:with-param name="string" select="text"/>
    </xsl:call-template>
    <xsl:choose>
      <xsl:when test="active='0'">
      </xsl:when>
      <xsl:when test="active='1' and string-length (end_time) &gt; 0">
        <xsl:text>Note active until: </xsl:text>
        <xsl:value-of select="end_time"/>
        <xsl:text>.</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>Note last modified: </xsl:text>
    <xsl:value-of select="modification_time"/>
    <xsl:text>.</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <xsl:template match="override">
    <xsl:param name="delta">0</xsl:param>
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
    <xsl:if test="$delta and $delta &gt; 0"> (Result <xsl:value-of select="$delta"/>)</xsl:if>
    <xsl:text>:</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="wrap">
      <xsl:with-param name="string" select="text"/>
    </xsl:call-template>
    <xsl:choose>
      <xsl:when test="active='0'">
      </xsl:when>
      <xsl:when test="active='1' and string-length (end_time) &gt; 0">
        <xsl:text>Override active until: </xsl:text>
        <xsl:value-of select="end_time"/>
        <xsl:text>.</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>Override last modified: </xsl:text>
    <xsl:value-of select="modification_time"/>
    <xsl:text>.</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Template for single issue -->
  <xsl:template match="result" mode="issue">
    <xsl:param name="report" select="/report"/>

    <xsl:call-template name="subsection">
      <xsl:with-param name="name">
        <xsl:choose>
          <xsl:when test="delta/text() = 'changed'">~ Changed Issue</xsl:when>
          <xsl:when test="delta/text() = 'gone'">- Removed Issue</xsl:when>
          <xsl:when test="delta/text() = 'new'">+ Added Issue</xsl:when>
          <xsl:when test="delta/text() = 'same'">= Equal Issue</xsl:when>
          <xsl:otherwise>Issue</xsl:otherwise>
        </xsl:choose>
      </xsl:with-param>
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

    <xsl:if test="count (detection)">
      <xsl:text>Product detection result: </xsl:text>
      <xsl:value-of select="detection/result/details/detail[name = 'product']/value/text()"/>
      <xsl:call-template name="newline"/>
      <xsl:text>Detected by: </xsl:text>
      <xsl:value-of select="detection/result/details/detail[name = 'source_name']/value/text()"/>
      <xsl:text> (OID: </xsl:text>
      <xsl:value-of select="detection/result/details/detail[name = 'source_oid']/value/text()"/>
      <xsl:text>)</xsl:text>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="newline"/>
    </xsl:if>

    <xsl:choose>
      <xsl:when test="delta/text() = 'changed'">
        <xsl:text>Result 1 Description:</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>Description:</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="newline"/>

    <xsl:call-template name="wrap">
      <xsl:with-param name="string" select="description"/>
    </xsl:call-template>
    <xsl:call-template name="newline"/>

    <xsl:apply-templates select="nvt"/>

    <xsl:if test="delta">
      <xsl:choose>
        <xsl:when test="delta/text() = 'changed'">
          <xsl:text>Result 2 Description:</xsl:text>
          <xsl:call-template name="newline"/>
          <xsl:call-template name="wrap">
            <xsl:with-param name="string" select="delta/result/description"/>
          </xsl:call-template>
          <xsl:call-template name="newline"/>

          <xsl:text>Different Lines:</xsl:text>
          <xsl:call-template name="newline"/>
          <xsl:call-template name="wrap">
            <xsl:with-param name="string" select="delta/diff"/>
          </xsl:call-template>
          <xsl:call-template name="newline"/>
        </xsl:when>
      </xsl:choose>
    </xsl:if>

    <xsl:variable name="delta">
      <xsl:choose>
        <xsl:when test="delta">1</xsl:when>
        <xsl:otherwise>0</xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:apply-templates select="notes/note">
      <xsl:with-param name="delta" select="$delta"/>
    </xsl:apply-templates>
    <xsl:apply-templates select="delta/notes/note">
      <xsl:with-param name="delta" select="2"/>
    </xsl:apply-templates>
    <xsl:if test="$report/filters/apply_overrides/text()='1'">
      <xsl:apply-templates select="overrides/override">
        <xsl:with-param name="delta" select="$delta"/>
      </xsl:apply-templates>
      <xsl:apply-templates select="delta/overrides/override">
        <xsl:with-param name="delta" select="2"/>
      </xsl:apply-templates>
    </xsl:if>

    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Template for single prognostic issue -->
  <xsl:template match="result" mode="prognostic-issue">
    <xsl:call-template name="subsection">
      <xsl:with-param name="name">Issue</xsl:with-param>
    </xsl:call-template>

    <xsl:text>Threat: </xsl:text>
    <xsl:value-of select="threat"/>
    <xsl:if test="string-length(cve/cvss_base) &gt; 0">
       <xsl:value-of select="concat(' (CVSS: ', cve/cvss_base,')')"/>
    </xsl:if>
    <xsl:call-template name="newline"/>
    <xsl:text>CVE:    </xsl:text>
    <xsl:value-of select="cve/@id"/>
    <xsl:call-template name="newline"/>
    <xsl:text>CPE:    </xsl:text>
    <xsl:value-of select="cve/cpe/@id"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="wrap">
      <xsl:with-param name="string" select="description"/>
    </xsl:call-template>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <xsl:template name="real-report">
    <xsl:choose>
      <xsl:when test="delta">
        <xsl:text>This document compares the results of two security scans.</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>The report first summarises the hosts found.  Then, for each host,</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>the report describes the changes that occurred between the two</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>scans.</xsl:text><xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="@type = 'prognostic'">
        <xsl:text>This document predicts the results of a security scan, based on</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>scan information already gathered for the hosts.</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>The report first summarises the results found.  Then, for each host,</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>the report describes every issue found.  Please consider the</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>advice given in each description, in order to rectify the issue.</xsl:text><xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>This document reports on the results of an automatic security scan.</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>The report first summarises the results found.</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>Then, for each host, the report describes every issue found.</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>Please consider the advice given in each description, in order to rectify</xsl:text><xsl:call-template name="newline"/>
        <xsl:text>the issue.</xsl:text><xsl:call-template name="newline"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="newline"/>

    <xsl:choose>
      <xsl:when test="@type = 'prognostic'">
      </xsl:when>
      <xsl:otherwise>
        <xsl:choose>
          <xsl:when test="filters/autofp/text()='1'">
            <xsl:text>Vendor security updates are trusted, using full CVE matching.</xsl:text>
          </xsl:when>
          <xsl:when test="filters/autofp/text()='2'">
            <xsl:text>Vendor security updates are trusted, using partial CVE matching.</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>Vendor security updates are not trusted.</xsl:text>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:call-template name="newline"/>
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
          <xsl:when test="filters/notes = 0">
            <xsl:text>Notes are excluded from the report.</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>Notes are included in the report.</xsl:text>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:call-template name="newline"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="newline"/>

    <xsl:text>This report might not show details of all issues that were found.</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:if test="filters/result_hosts_only = 1">
      <xsl:text>It only lists hosts that produced issues.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="string-length(filters/phrase) &gt; 0">
      <xsl:text>It shows issues that contain the search phrase "</xsl:text>
      <xsl:value-of select="filters/phrase"/>
      <xsl:text>".</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(filters/text(), 'h') = false">
      <xsl:text>Issues with the threat level "High" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(filters/text(), 'm') = false">
      <xsl:text>Issues with the threat level "Medium" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(filters/text(), 'l') = false">
      <xsl:text>Issues with the threat level "Low" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(filters/text(), 'g') = false">
      <xsl:text>Issues with the threat level "Log" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(filters/text(), 'd') = false">
      <xsl:text>Issues with the threat level "Debug" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="contains(filters/text(), 'f') = false">
      <xsl:text>Issues with the threat level "False Positive" are not shown.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:call-template name="newline"/>

    <xsl:variable name="last" select="results/@start + count(results/result) - 1"/>
    <xsl:choose>
      <xsl:when test="$last = 0">
        <xsl:text>This report contains 0 results.</xsl:text>
      </xsl:when>
      <xsl:when test="$last = results/@start">
        <xsl:text>This report contains result </xsl:text>
        <xsl:value-of select="$last"/>
        <xsl:text> of the </xsl:text>
        <xsl:value-of select="result_count/filtered"/>
        <xsl:text> results selected by the</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>filtering above.</xsl:text>
      </xsl:when>
      <xsl:when test="$last = result_count/filtered">
        <xsl:text>This report contains all </xsl:text>
        <xsl:value-of select="result_count/filtered"/>
        <xsl:text> results selected by the</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>filtering described above.</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>This report contains results </xsl:text>
        <xsl:value-of select="results/@start"/>
        <xsl:text> to </xsl:text>
        <xsl:value-of select="$last"/>
        <xsl:text> of the </xsl:text>
        <xsl:value-of select="result_count/filtered"/>
        <xsl:text> results selected by the</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>filtering described above.</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:choose>
      <xsl:when test="@type = 'prognostic'">
      </xsl:when>
      <xsl:when test="delta">
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>  Before filtering there were </xsl:text>
        <xsl:value-of select="result_count/text()"/>
        <xsl:text> results.</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:choose>
      <xsl:when test="@type = 'prognostic'">
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>Scan started: </xsl:text><xsl:call-template name="scan_start"/><xsl:call-template name="newline"/>
        <xsl:text>Scan ended:   </xsl:text>
        <xsl:call-template name="scan_end"/><xsl:call-template name="newline"/>
        <xsl:call-template name="newline"/>
      </xsl:otherwise>
    </xsl:choose>

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
    <xsl:for-each select="host" >
      <xsl:variable name="current_host" select="ip" />
      <xsl:variable name="hostname" select="detail[name/text() = 'hostname']/value"/>
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
      <xsl:if test="$hostname">
        <xsl:call-template name="text-align-right">
          <xsl:with-param name="width" select="string-length ($hostname) + 4"/>
          <xsl:with-param name="content" select="$hostname"/>
        </xsl:call-template>
      </xsl:if>
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

    <xsl:variable name="report" select="." />
    <xsl:for-each select="host" >
      <xsl:variable name="current_host" select="ip" />
      <xsl:call-template name="section">
        <xsl:with-param name="name" select="concat('Host ', $current_host)"/>
      </xsl:call-template>
      <xsl:call-template name="newline"/>

      <xsl:choose>
        <xsl:when test="$report/@type = 'prognostic'">
          <xsl:text>Number of results: </xsl:text>
          <xsl:value-of select="count(../results/result[host/text()=$current_host])"/>
          <xsl:call-template name="newline"/>
          <xsl:call-template name="newline"/>

          <xsl:call-template name="subsection">
            <xsl:with-param name="name">Security Issues for Host <xsl:value-of select="$current_host" /></xsl:with-param>
          </xsl:call-template>
          <xsl:call-template name="newline"/>

          <xsl:apply-templates select="../results/result[host/text()=$current_host]" mode="prognostic-issue"/>
        </xsl:when>
        <xsl:otherwise>
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

          <xsl:variable name="cves" select="str:split(detail[name = 'Closed CVEs']/value, ',')"/>
          <xsl:choose>
            <xsl:when test="$report/@type = 'delta'">
            </xsl:when>
            <xsl:when test="$report/filters/show_closed_cves = 1">
              <xsl:call-template name="subsection">
                <xsl:with-param name="name">Closed CVEs for Host <xsl:value-of select="$current_host" /></xsl:with-param>
              </xsl:call-template>
              <xsl:call-template name="newline"/>

              <xsl:variable name="t3-col1-width" select="24"/>
              <xsl:call-template name="text-align-left">
                <xsl:with-param name="width" select="$t3-col1-width"/>
                <xsl:with-param name="content">CVE</xsl:with-param>
              </xsl:call-template>
              <xsl:text>NVT</xsl:text>
              <xsl:call-template name="newline"/>
              <xsl:variable name="host" select="."/>
              <xsl:for-each select="$cves">
                <xsl:variable name="cve" select="normalize-space(.)"/>
                <xsl:call-template name="text-align-left">
                  <xsl:with-param name="width" select="$t3-col1-width"/>
                  <xsl:with-param name="content" select="$cve"/>
                </xsl:call-template>
                <xsl:variable name="closed_cve"
                              select="$host/detail[name = 'Closed CVE' and contains(value, $cve)]"/>
                <xsl:value-of select="$closed_cve/source/description"/>
                <xsl:call-template name="newline"/>
              </xsl:for-each>
              <xsl:call-template name="newline"/>
            </xsl:when>
          </xsl:choose>

          <xsl:call-template name="subsection">
            <xsl:with-param name="name">Security Issues for Host <xsl:value-of select="$current_host" /></xsl:with-param>
          </xsl:call-template>
          <xsl:call-template name="newline"/>

          <xsl:apply-templates select="../results/result[host/text()=$current_host]" mode="issue">
            <xsl:with-param name="report" select="$report"/>
          </xsl:apply-templates>
        </xsl:otherwise>
      </xsl:choose>

    </xsl:for-each>
  </xsl:template>

  <xsl:template match="report">
    <xsl:choose>
      <xsl:when test="@extension='xml'">
        <xsl:apply-templates select="report"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="chapter">
          <xsl:with-param name="name">
            <xsl:choose>
              <xsl:when test="delta">I Delta Report Summary</xsl:when>
              <xsl:when test="@type = 'prognostic'">I Prognostic Report Summary</xsl:when>
              <xsl:otherwise>I Summary</xsl:otherwise>
            </xsl:choose>
          </xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="newline"/>
        <xsl:call-template name="real-report"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Match the root. -->
  <xsl:template match="/">
    <xsl:apply-templates/>
  </xsl:template>

</xsl:stylesheet>
