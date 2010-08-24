<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output
    method = "text"
    indent = "no" />

<!--
OpenVAS Manager
$Id$
Description: Stylesheet for generating results as dot file.

Authors:
Michael Wiegand <michael.wiegand@greenbone.net>

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

  <xsl:template match="report">
digraph scan {
  nodesep = 8;
  ranksep = 2;
  overlap = "true";
  fontsize = 8.0;
  concentrate = "true";
  root = "OpenVAS";
  "OpenVAS" [style=filled, color=chartreuse3];
    <xsl:for-each select="host_start" >
      <xsl:variable name="current_host" select="host/text()"/>
      <xsl:choose>
        <xsl:when test="count(../results/result[host/text() = $current_host][threat/text() = 'High']) &gt; 0">
  "<xsl:value-of select="$current_host"/>" [style=filled, color=red, fontcolor=white];
        </xsl:when>
        <xsl:otherwise>
          <xsl:choose>
            <xsl:when test="count(../results/result[host/text() = $current_host][threat/text() = 'Medium']) &gt; 0">
  "<xsl:value-of select="$current_host"/>" [style=filled, color=orange, fontcolor=white];
            </xsl:when>
            <xsl:otherwise>
              <xsl:choose>
                <xsl:when test="count(../results/result[host/text() = $current_host][threat/text() = 'Low']) &gt; 0">
  "<xsl:value-of select="$current_host"/>" [style=filled, color=cornflowerblue, fontcolor=white];
                </xsl:when>
              </xsl:choose>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:apply-templates select="../results/result[host/text() = $current_host][port/text() = 'general/HOST-T']" mode="trace">
        <xsl:with-param name="host" select="$current_host" />
      </xsl:apply-templates>
    </xsl:for-each>
}
  </xsl:template>

  <xsl:template match="result" mode="trace">
    <xsl:param name="host"/>
    <xsl:variable name="space"><xsl:text>
</xsl:text>
    </xsl:variable>
    <xsl:variable name="fullroute" select="substring-before(substring-after(description/text(), 'traceroute:'), $space)" />
    <xsl:variable name="ports" select="substring-before(substring-after(description/text(), 'ports:'), $space)" />
    <xsl:variable name="gsm" select="substring-before($fullroute, ',')" />
    <xsl:variable name="route" select="substring-after($fullroute, ',')" />
    <xsl:variable name="nexthop" select="substring-before($route, ',')" />
    <xsl:choose>
      <xsl:when test="contains($route, ',')">
        "OpenVAS" -> "<xsl:value-of select="$nexthop"/>";
        <xsl:call-template name="trace_recurse">
          <xsl:with-param name="trace_list" select="$route"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:choose>
          <xsl:when test="$route">
            "OpenVAS" -> "<xsl:value-of select="$route"/>";
          </xsl:when>
          <xsl:otherwise>
            "OpenVAS" -> "127.0.0.1" [style=dashed];
          </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
    <!-- Enable the following block for experimental port visualisation -->
    <!--    <xsl:call-template name="port_recurse">
      <xsl:with-param name="port_list" select="$ports"/>
      <xsl:with-param name="port_host" select="$host"/>
    </xsl:call-template> -->
  </xsl:template>

  <xsl:template name="trace_recurse">
    <xsl:param name="trace_list"/>
    <xsl:choose>
      <xsl:when test="contains($trace_list, ',')">
        <xsl:variable name="head" select="substring-before($trace_list, ',')" />
        <xsl:variable name="tail" select="substring-after($trace_list, ',')"/>
        <xsl:variable name="next" select="substring-before($tail, ',')"/>
        <xsl:choose>
          <xsl:when test="($next) and not ($head = $next) and not (contains ($head, '*')) and not (contains ($next, '*'))">
            "<xsl:value-of select="$head"/>" -> "<xsl:value-of select="$next"/>";
          </xsl:when>
          <xsl:when test="not ($next) and ($tail) and not ($head = $tail) and not (contains ($head, '*')) and not (contains ($tail, '*'))">
            "<xsl:value-of select="$head"/>" -> "<xsl:value-of select="$tail"/>";
          </xsl:when>
        </xsl:choose>
        <xsl:call-template name="trace_recurse">
          <xsl:with-param name="trace_list" select="$tail"/>
        </xsl:call-template>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="port_recurse">
    <xsl:param name="port_list"/>
    <xsl:param name="port_host"/>
    <xsl:choose>
      <xsl:when test="contains($port_list, ',')">
        <xsl:variable name="head" select="substring-before($port_list, ',')" />
        <xsl:variable name="tail" select="substring-after($port_list, ',')"/>
        "<xsl:value-of select="$port_host"/>:<xsl:value-of select="$head"/>" [label ="<xsl:value-of select="$head"/>", shape="triangle"];
        "<xsl:value-of select="$port_host"/>" -> "<xsl:value-of select="$port_host"/>:<xsl:value-of select="$head"/>" [len = 0.2];
        <xsl:call-template name="port_recurse">
          <xsl:with-param name="port_list" select="$tail"/>
          <xsl:with-param name="port_host" select="$port_host"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="$port_list and not (contains($port_list, ','))">
        "<xsl:value-of select="$port_host"/>:<xsl:value-of select="$port_list"/>" [label ="<xsl:value-of select="$port_list"/>", shape="triangle"];
        "<xsl:value-of select="$port_host"/>" -> "<xsl:value-of select="$port_host"/>:<xsl:value-of select="$port_list"/>" [len = 0.2];
      </xsl:when>
    </xsl:choose>
  </xsl:template>
</xsl:stylesheet>

