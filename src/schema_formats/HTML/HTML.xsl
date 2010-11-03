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
  <xsl:strip-space elements="pretty"/>

<!--
OpenVAS Manager
$Id$
Description: OpenVAS Manager Protocol (OMP) single page HTML doc generator.

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

  <xsl:variable name="rnc-comments">0</xsl:variable>
  <xsl:include href="rnc.xsl"/>

  <!-- Helpers. -->

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="description">
    <xsl:choose>
      <xsl:when test="(count(*) = 0) and (string-length(normalize-space(text())) &gt; 0)">
        <p><xsl:value-of select="text()"/></p>
      </xsl:when>
      <xsl:otherwise>
        <xsl:for-each select="*">
          <xsl:choose>
            <xsl:when test="name()='p'">
              <p><xsl:value-of select="text()"/></p>
            </xsl:when>
            <xsl:when test="name()='l'">
              <p>
                <xsl:value-of select="lh"/>
                <ul>
                  <xsl:for-each select="li">
                    <li><xsl:value-of select="text()"/></li>
                  </xsl:for-each>
                </ul>
                <xsl:value-of select="lf"/>
              </p>
            </xsl:when>
          </xsl:choose>
        </xsl:for-each>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Called within a PRE. -->
  <xsl:template name="print-space">
    <xsl:param name="count">1</xsl:param>
    <xsl:text> </xsl:text>
    <xsl:if test="$count &gt; 0">
      <xsl:call-template name="print-space">
        <xsl:with-param name="count" select="$count - 1"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- Called within a PRE. -->
  <xsl:template name="print-attributes">
    <xsl:for-each select="attribute::*">
      <xsl:text> </xsl:text>
      <xsl:value-of select="name()"/>
      <xsl:text>="</xsl:text>
      <xsl:value-of select="."/>
      <xsl:text>"</xsl:text>
    </xsl:for-each>
  </xsl:template>

  <!-- Called within a PRE. -->
  <xsl:template name="pretty">
    <xsl:param name="level">0</xsl:param>
    <xsl:call-template name="print-space">
      <xsl:with-param name="count" select="$level * 2"/>
    </xsl:call-template>
    <xsl:choose>
      <xsl:when test="name()='truncated'">
        <xsl:text>...</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="(count(*) = 0) and (string-length(normalize-space(text())) = 0)">
        <xsl:text>&lt;</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:call-template name="print-attributes"/>
        <xsl:text>/&gt;</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="(count(*) = 0) and (string-length(text()) &lt;= 60)">
        <xsl:text>&lt;</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:call-template name="print-attributes"/>
        <xsl:text>&gt;</xsl:text>
        <xsl:value-of select="text()"/>
        <xsl:text>&lt;/</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:text>&gt;</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>&lt;</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:call-template name="print-attributes"/>
        <xsl:text>&gt;</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:if test="string-length(normalize-space(text())) &gt; 0">
          <xsl:call-template name="print-space">
            <xsl:with-param name="count" select="$level * 2 + 2"/>
          </xsl:call-template>
          <xsl:value-of select="normalize-space(text())"/>
          <xsl:call-template name="newline"/>
        </xsl:if>
        <xsl:for-each select="*">
          <xsl:call-template name="pretty">
            <xsl:with-param name="level" select="$level + 1"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:call-template name="print-space">
          <xsl:with-param name="count" select="$level * 2"/>
        </xsl:call-template>
        <xsl:text>&lt;/</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:text>&gt;</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Commands. -->

  <xsl:template name="command-relax">
    <pre><xsl:call-template name="command-body"/></pre>
  </xsl:template>

  <xsl:template name="response-relax">
    <pre><xsl:call-template name="response-body"/></pre>
  </xsl:template>

  <xsl:template match="type">
    <xsl:choose>
      <xsl:when test="count (alts) &gt; 0">
        <xsl:for-each select="alts/alt">
          <xsl:choose>
            <xsl:when test="following-sibling::alt and preceding-sibling::alt">
              <xsl:text>, </xsl:text>
            </xsl:when>
            <xsl:when test="count (following-sibling::alt) = 0">
              <xsl:text> or </xsl:text>
            </xsl:when>
            <xsl:otherwise>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:text>"</xsl:text>
          <xsl:value-of select="."/>
          <xsl:text>"</xsl:text>
        </xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="text()"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="breakdown-line">
    <xsl:param name="line-element"/>
    <xsl:param name="element-suffix"/>
    <xsl:choose>
      <xsl:when test="name() = 'any'">
        <xsl:for-each select="*">
          <xsl:call-template name="breakdown-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="element-suffix" select="'*'"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'attrib'">
        <li>
          <b>"<xsl:value-of select="name"/>"</b>
          (<xsl:apply-templates select="type"/>)
          <xsl:if test="summary">
            <xsl:value-of select="normalize-space(summary)"/>.
          </xsl:if>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'r'">
        <li>
          <xsl:variable name="element-name" select="text()"/>
          <b>
            &lt;<xsl:value-of select="text()"/>&gt;<xsl:value-of select="$element-suffix"/>
          </b>
          <div style="margin-left: 15px; display: inline;">
            A response to a <a href="#{$element-name}"><xsl:value-of select="$element-name"/></a> command.
          </div>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'e'">
        <li>
          <xsl:variable name="element-name" select="text()"/>
          <xsl:variable name="new-line-element"
                        select="$line-element/ele[name=$element-name]"/>
          <b>
            &lt;<xsl:value-of select="text()"/>&gt;<xsl:value-of select="$element-suffix"/>
          </b>
          <xsl:if test="$new-line-element/summary">
            <div style="margin-left: 15px; display: inline;"><xsl:value-of select="normalize-space($new-line-element/summary)"/>.</div>
          </xsl:if>
          <ul style="list-style: none">
            <xsl:for-each select="$new-line-element/pattern/*">
              <xsl:call-template name="breakdown-line">
                <xsl:with-param name="line-element" select="$new-line-element"/>
              </xsl:call-template>
            </xsl:for-each>
          </ul>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'g'">
        <li>
          <i>The group</i><b><xsl:value-of select="$element-suffix"/></b>
          <ul style="list-style: none">
            <xsl:for-each select="*">
              <xsl:call-template name="breakdown-line">
                <xsl:with-param name="line-element" select="$line-element"/>
              </xsl:call-template>
            </xsl:for-each>
          </ul>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'o'">
        <xsl:for-each select="*">
          <xsl:call-template name="breakdown-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="element-suffix" select="'?'"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'or'">
        <li>
          <i>One of</i>
          <ul style="list-style: none">
            <xsl:for-each select="*">
              <xsl:call-template name="breakdown-line">
                <xsl:with-param name="line-element" select="$line-element"/>
              </xsl:call-template>
            </xsl:for-each>
          </ul>
        </li>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="command-breakdown">
    <ul style="list-style: none">
      <xsl:choose>
        <xsl:when test="(count(pattern/*) = 0) and (string-length(normalize-space(pattern)) = 0)">
          <i>Empty single element.</i>
        </xsl:when>
        <xsl:otherwise>
          <xsl:variable name="command" select="."/>
          <xsl:for-each select="pattern/*">
            <xsl:call-template name="breakdown-line">
              <xsl:with-param name="line-element" select="$command"/>
            </xsl:call-template>
          </xsl:for-each>
        </xsl:otherwise>
      </xsl:choose>
    </ul>
  </xsl:template>

  <xsl:template match="command">
    <xsl:param name="index">2.<xsl:value-of select="position()"/></xsl:param>
    <div>
      <div>
        <h3 id="{name}">
          <xsl:value-of select="$index"/>
          Command <tt><xsl:value-of select="name"/></tt></h3>
      </div>

      <p><b>In short: </b><xsl:value-of select="normalize-space(summary)"/>.</p>

      <xsl:apply-templates select="description"/>

      <h4><xsl:value-of select="$index"/>.1 Breakdown</h4>

      <ul style="list-style: none">
        <li>
          <div style="font-weight:bold;">Command</div>
          <xsl:call-template name="command-breakdown"/>
        </li>
        <li>
          <div style="font-weight:bold;">Response</div>
          <xsl:for-each select="response">
            <xsl:call-template name="command-breakdown"/>
          </xsl:for-each>
        </li>
      </ul>

      <h4><xsl:value-of select="$index"/>.2 RNC</h4>

      <div style="border: 1px solid; padding:10px; width: 75%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
        <div style="font-weight:bold;">Command</div>
        <xsl:call-template name="command-relax"/>
        <div style="font-weight:bold;">Response</div>
        <xsl:call-template name="response-relax"/>
      </div>

      <xsl:choose>
        <xsl:when test="count(example) &gt; 0">
          <xsl:for-each select="example">
            <h4><xsl:value-of select="$index"/>.1 Example: <xsl:value-of select="summary"/></h4>
            <xsl:apply-templates select="description"/>
            <b>Client:</b><br/>
            <xsl:for-each select="request/*">
              <pre>
                <xsl:call-template name="pretty"/>
              </pre>
            </xsl:for-each>
            <br/>
            <b>Manager:</b><br/>
            <xsl:for-each select="response/*">
              <pre>
                <xsl:call-template name="pretty"/>
              </pre>
            </xsl:for-each>
          </xsl:for-each>
        </xsl:when>
        <xsl:otherwise>
        </xsl:otherwise>
      </xsl:choose>

    </div>
  </xsl:template>

  <xsl:template match="command" mode="index">
    <tr id="index">
      <td id="index"><a href="#{name}"><xsl:value-of select="name"/></a></td>
      <td id="index"><div style="margin-left: 15px;"><xsl:value-of select="normalize-space(summary)"/>.</div></td>
    </tr>
  </xsl:template>

  <xsl:template name="command-summary">
    <h2 id="command_summary">1 Summary of Commands</h2>
    <table id="index">
    <xsl:apply-templates select="command" mode="index"/>
    </table>
  </xsl:template>

  <xsl:template name="command-details">
    <h2 id="command_summary">2 Command Details</h2>
    <xsl:apply-templates select="command"/>
  </xsl:template>

  <!-- Root. -->

  <xsl:template match="protocol">
    <html>
      <head>
        <title>
          <xsl:choose>
            <xsl:when test="abbreviation">
              <xsl:value-of select="abbreviation"/>
            </xsl:when>
            <xsl:when test="name">
              <xsl:value-of select="name"/>
            </xsl:when>
            <xsl:otherwise>
              Protocol definition
            </xsl:otherwise>
          </xsl:choose>
        </title>
      </head>
      <body style="background-color: #FFFFFF; margin: 0px; font: small Verdana, sans-serif; font-size: 12px; color: #1A1A1A;">
        <div style="width: 98%; width:700px; align: center; margin-left: auto; margin-right: auto;">
          <table style="width: 100%;" cellpadding="3" cellspacing="0">
            <tr>
              <td valign="top">
                <h1>
                  <xsl:if test="abbreviation">
                    <xsl:value-of select="abbreviation"/>:
                  </xsl:if>
                  <xsl:value-of select="name"/>
                </h1>

                <xsl:if test="version">
                  <p>Version: <xsl:value-of select="normalize-space(version)"/></p>
                </xsl:if>

                <xsl:if test="summary">
                  <p><xsl:value-of select="normalize-space(summary)"/>.</p>
                </xsl:if>

                <xsl:call-template name="command-summary"/>
                <xsl:call-template name="command-details"/>

                <div style="text-align: center; padding: 5px;">
                  This file was automatically generated.
                </div>
              </td>
            </tr>
          </table>
        </div>
      </body>
    </html>
  </xsl:template>

  <xsl:template match="/">
    <xsl:apply-templates select="protocol"/>
  </xsl:template>

</xsl:stylesheet>
