<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:func = "http://exslt.org/functions"
    extension-element-prefixes="str func">
  <xsl:output method="text" encoding="string" indent="no"/>
  <xsl:strip-space elements="*"/>

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

<!-- Greenbone Management Protocol (GMP) single page HTML doc generator. -->

  <xsl:variable name="rnc-comments">0</xsl:variable>
  <xsl:include href="rnc.xsl"/>

  <!-- Helpers. -->

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

  <!-- Remove leading newlines, leaving other newlines intact. -->
  <func:function name="func:string-left-trim-nl">
    <xsl:param name="string"/>
    <xsl:choose>
      <xsl:when test="string-length($string) = 0">
        <func:result select="''"/>
      </xsl:when>
      <xsl:when test="starts-with($string,'&#10;')">
        <func:result select="func:string-left-trim-nl(substring($string,2))"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="$string"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Remove trailing newlines, leaving other newlines intact. -->
  <func:function name="func:string-right-trim-nl">
    <xsl:param name="string"/>
    <xsl:choose>
      <xsl:when test="string-length($string) = 0">
        <func:result select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="last"
                      select="substring($string, string-length($string))"/>
        <xsl:choose>
          <xsl:when test="$last = '&#10;' or $last = ' '">
            <func:result
              select="func:string-right-trim-nl(substring($string,1,string-length($string) - 1))"/>
          </xsl:when>
          <xsl:otherwise>
            <func:result select="$string"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Remove leading and trailing newlines, leaving other newlines
       intact. -->
  <func:function name="func:string-trim-nl">
    <xsl:param name="string"/>
    <func:result
      select="func:string-left-trim-nl(func:string-right-trim-nl($string))"/>
  </func:function>

  <xsl:template match="description">
    <xsl:value-of select="normalize-space (text ())"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Called within a PRE. -->
  <xsl:template name="print-space">
    <xsl:param name="count">1</xsl:param>
    <xsl:if test="$count &gt; 0">
      <xsl:text> </xsl:text>
      <xsl:call-template name="print-space">
        <xsl:with-param name="count" select="$count - 1"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <xsl:template name="print-bullet">
    <xsl:param name="depth">0</xsl:param>
    <xsl:text>*</xsl:text>
    <xsl:if test="$depth &gt; 0">
      <xsl:call-template name="print-bullet">
        <xsl:with-param name="depth" select="$depth - 1"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <xsl:template name="bullet">
    <xsl:param name="depth">0</xsl:param>
    <xsl:call-template name="print-space">
      <xsl:with-param name="count" select="$depth"/>
    </xsl:call-template>
    <xsl:call-template name="print-bullet">
      <xsl:with-param name="depth" select="$depth"/>
    </xsl:call-template>
    <xsl:text> </xsl:text>
  </xsl:template>

  <!-- Called within a PRE. -->
  <xsl:template name="print-attributes">
    <xsl:param name="level">0</xsl:param>
    <xsl:variable name="indent" select="string-length(name()) + 2"/>
    <xsl:for-each select="attribute::*">
      <xsl:choose>
        <xsl:when test="position() = 1">
          <xsl:text> </xsl:text>
          <xsl:value-of select="name()"/>
          <xsl:text>="</xsl:text>
          <xsl:value-of select="."/>
          <xsl:text>"</xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="newline"/>
          <xsl:call-template name="print-space">
            <xsl:with-param name="count" select="$level * 2 + $indent"/>
          </xsl:call-template>
          <xsl:value-of select="name()"/>
          <xsl:text>="</xsl:text>
          <xsl:value-of select="."/>
          <xsl:text>"</xsl:text>
        </xsl:otherwise>
      </xsl:choose>
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
        <xsl:call-template name="print-attributes">
          <xsl:with-param name="level" select="$level"/>
        </xsl:call-template>
        <xsl:text>/&gt;</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="(count(*) = 0) and (string-length(text()) &lt;= 60)">
        <xsl:text>&lt;</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:call-template name="print-attributes">
          <xsl:with-param name="level" select="$level"/>
        </xsl:call-template>
        <xsl:text>&gt;</xsl:text>
        <xsl:value-of select="normalize-space(text())"/>
        <xsl:text>&lt;/</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:text>&gt;</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>&lt;</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:call-template name="print-attributes">
          <xsl:with-param name="level" select="$level"/>
        </xsl:call-template>
        <xsl:text>&gt;</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:choose>
          <xsl:when test="name() = 'help_response' or name() = 'p'">
            <!-- Special case certain responses to preserve whitespace. -->
            <xsl:variable name="string" select="func:string-trim-nl(text())"/>
            <xsl:if test="string-length($string) &gt; 0">
              <xsl:value-of select="$string"/>
              <xsl:call-template name="newline"/>
            </xsl:if>
          </xsl:when>
          <xsl:otherwise>
            <xsl:if test="string-length(normalize-space(text())) &gt; 0">
              <xsl:call-template name="print-space">
                <xsl:with-param name="count" select="$level * 2 + 2"/>
              </xsl:call-template>
              <xsl:value-of select="normalize-space(text())"/>
              <xsl:call-template name="newline"/>
            </xsl:if>
          </xsl:otherwise>
        </xsl:choose>
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

  <!-- RNC preamble. -->

  <xsl:template name="rnc-preamble">
    <h2 id="rnc_preamble">4 RNC Preamble</h2>
    <div style="border: 1px solid; padding:10px; width: 85%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
      <pre>
        <xsl:call-template name="preamble"/>
      </pre>
    </div>
  </xsl:template>

  <!-- Types. -->

  <xsl:template match="type" mode="index">
    <xsl:value-of select="name"/>
    <xsl:text>:: </xsl:text>
    <xsl:if test="summary">
      <xsl:value-of select="normalize-space(summary)"/>
      <xsl:text>+</xsl:text>
    </xsl:if>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <xsl:template name="type-summary">
    <xsl:text>=== Summary of Data Types</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:text>[horizontal]</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:apply-templates select="type" mode="index"/>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <xsl:template match="type" mode="details">
    <xsl:text>==== Data Type `</xsl:text>
    <xsl:value-of select="name"/>
    <xsl:text>`</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:if test="summary">
      <xsl:text>_In short:_ </xsl:text>
      <xsl:value-of select="normalize-space(summary)"/>
      <xsl:text>.</xsl:text>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="newline"/>
    </xsl:if>

    <xsl:apply-templates select="description"/>
  </xsl:template>

  <xsl:template name="type-details">
    <xsl:text>=== Data Types</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:apply-templates select="type" mode="details"/>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Elements. -->

  <xsl:template match="element" mode="index">
    <tr id="index">
      <td id="index"><a href="#element_{name}"><xsl:value-of select="name"/></a></td>
      <td id="index">
        <xsl:if test="summary">
          <div style="margin-left: 15px;"><xsl:value-of select="normalize-space(summary)"/>.</div>
        </xsl:if>
      </td>
    </tr>
  </xsl:template>

  <xsl:template name="element-summary">
=== Summary of Elements
    <table id="index">
    <xsl:apply-templates select="element" mode="index"/>
    </table>
  </xsl:template>

  <xsl:template name="element-details">
    <xsl:text>=== Elements</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:apply-templates select="element"/>
  </xsl:template>

  <xsl:template match="element">
    <xsl:text>==== Element `</xsl:text>
    <xsl:value-of select="name"/>
    <xsl:text>`</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:if test="summary">
      <xsl:text>_In short:_ </xsl:text>
      <xsl:value-of select="normalize-space(summary)"/>
      <xsl:text>.</xsl:text>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="newline"/>
    </xsl:if>

    <xsl:apply-templates select="description"/>

    <xsl:text>===== Structure</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:call-template name="command-structure"/>
  </xsl:template>

  <!-- Commands. -->

  <xsl:template name="command-relax">
    <pre><xsl:call-template name="command-body"/></pre>
  </xsl:template>

  <xsl:template name="response-relax">
    <pre><xsl:call-template name="response-body"/></pre>
  </xsl:template>

  <xsl:template match="type" mode="element">
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
      <xsl:when test="normalize-space(text()) = 'text'">
        <xsl:text>text</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <a href="#element_{text()}"><xsl:value-of select="text()"/></a>
      </xsl:otherwise>
    </xsl:choose>
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
      <xsl:when test="normalize-space(text()) = 'text'">
        <xsl:text>text</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <a href="#type_{text()}"><xsl:value-of select="text()"/></a>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="structure-line">
    <xsl:param name="depth">0</xsl:param>
    <xsl:param name="line-element"/>
    <xsl:param name="element-suffix"/>
    <xsl:choose>
      <xsl:when test="name() = 'any'">
        <xsl:for-each select="*">
          <xsl:call-template name="structure-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="element-suffix" select="' * '"/>
            <xsl:with-param name="depth" select="$depth + 1"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'attrib'">
        <xsl:call-template name="bullet">
          <xsl:with-param name="depth" select="$depth"/>
        </xsl:call-template>
        <xsl:text>`@</xsl:text>
        <xsl:value-of select="name"/>
        <xsl:text>` (</xsl:text>
        <xsl:apply-templates select="type"/>
        <xsl:text>)</xsl:text>
        <xsl:if test="summary">
          <xsl:text> </xsl:text>
          <xsl:value-of select="normalize-space(summary)"/>.
        </xsl:if>
        <xsl:call-template name="newline"/>
        <xsl:apply-templates select="filter_keywords"/>
      </xsl:when>
      <xsl:when test="name() = 'c'">
        <xsl:call-template name="bullet">
          <xsl:with-param name="depth" select="$depth"/>
        </xsl:call-template>
        <xsl:variable name="element-name" select="text()"/>
        <xsl:text>`$$&lt;</xsl:text>
        <xsl:value-of select="text()"/>
        <xsl:text>&gt;$$`</xsl:text>
        <xsl:value-of select="$element-suffix"/>
<!-- FIX link -->
        <xsl:text> </xsl:text>
        <xsl:value-of select="$element-name"/>
        <xsl:text> command.</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="name() = 'r'">
        <xsl:call-template name="bullet">
          <xsl:with-param name="depth" select="$depth"/>
        </xsl:call-template>
        <xsl:variable name="element-name" select="text()"/>
        <xsl:text>`$$&lt;</xsl:text>
        <xsl:value-of select="text()"/>
        <xsl:text>&gt;$$`</xsl:text>
        <xsl:value-of select="$element-suffix"/>
<!-- FIX link -->
        <xsl:text> Response to </xsl:text>
        <xsl:value-of select="$element-name"/>
        <xsl:text> command</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="name() = 'e'">
        <xsl:variable name="element-name" select="text()"/>
        <xsl:variable name="new-line-element"
                      select="$line-element/ele[name=$element-name]"/>
        <xsl:choose>
          <xsl:when test="$new-line-element">
            <xsl:call-template name="bullet">
              <xsl:with-param name="depth" select="$depth"/>
            </xsl:call-template>
            <xsl:text>`$$&lt;</xsl:text>
            <xsl:value-of select="text()"/>
            <xsl:text>&gt;$$` </xsl:text>
            <xsl:value-of select="$element-suffix"/>
            <xsl:if test="$new-line-element/type">
              <xsl:text> (</xsl:text>
              <xsl:apply-templates select="$new-line-element/type" mode="element"/>
              <xsl:text>) </xsl:text>
            </xsl:if>
            <xsl:if test="$new-line-element/summary">
              <xsl:value-of select="normalize-space($new-line-element/summary)"/>
              <xsl:text>.</xsl:text>
            </xsl:if>
            <xsl:call-template name="newline"/>
            <xsl:for-each select="$new-line-element/pattern/*">
              <xsl:call-template name="structure-line">
                <xsl:with-param name="line-element" select="$new-line-element"/>
                <xsl:with-param name="depth" select="$depth + 1"/>
              </xsl:call-template>
            </xsl:for-each>
          </xsl:when>
          <xsl:otherwise>
            <xsl:variable name="global-element"
                          select="/protocol/element[name=$element-name]"/>
<!-- FIX link? href="#element_{$global-element/name} -->
            <xsl:call-template name="bullet">
              <xsl:with-param name="depth" select="$depth"/>
            </xsl:call-template>
            <xsl:text>`$$&lt;</xsl:text>
            <xsl:value-of select="text()"/>
            <xsl:text>&gt;$$` </xsl:text>
            <xsl:value-of select="$element-suffix"/>
            <xsl:value-of select="normalize-space($global-element/summary)"/>
            <xsl:text>.</xsl:text>
            <xsl:call-template name="newline"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:when test="name() = 'g'">
        <xsl:call-template name="bullet">
          <xsl:with-param name="depth" select="$depth"/>
        </xsl:call-template>
        <xsl:text>_The group *</xsl:text>
        <xsl:value-of select="$element-suffix"/>
        <xsl:text>*_</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:for-each select="*">
          <xsl:call-template name="structure-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="depth" select="$depth + 1"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'o'">
        <xsl:for-each select="*">
          <xsl:call-template name="structure-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="element-suffix" select="' ? '"/>
            <xsl:with-param name="depth" select="$depth + 1"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'or'">
        <xsl:call-template name="bullet">
          <xsl:with-param name="depth" select="$depth"/>
        </xsl:call-template>
        <xsl:text>_One of *</xsl:text>
        <xsl:value-of select="$element-suffix"/>
        <xsl:text>*_</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:for-each select="*">
          <xsl:call-template name="structure-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="depth" select="$depth + 1"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="command-structure">
    <xsl:choose>
      <xsl:when test="(count(pattern/*) = 0) and (string-length(normalize-space(pattern)) = 0)">
        <xsl:text>_Empty single element._</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="(count(pattern/*) = 0) and (string-length(normalize-space(pattern)) &gt; 0)">
        <xsl:value-of select="normalize-space(pattern)"/>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="command" select="."/>
        <xsl:text>--</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:for-each select="pattern/*">
          <xsl:call-template name="structure-line">
            <xsl:with-param name="line-element" select="$command"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:text>--</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <xsl:template match="command">
    <xsl:text>==== Command `</xsl:text>
    <xsl:value-of select="name"/>
    <xsl:text>`</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:if test="summary">
      <xsl:text>_In short:_ </xsl:text>
      <xsl:value-of select="normalize-space(summary)"/>
      <xsl:text>.</xsl:text>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="newline"/>
    </xsl:if>

    <xsl:apply-templates select="description"/>

    <xsl:text>===== Structure</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:text>_Command_</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="command-structure"/>

    <xsl:text>_Response_</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="response">
      <xsl:call-template name="command-structure"/>
    </xsl:for-each>

    <xsl:choose>
      <xsl:when test="count(example) &gt; 0">
        <xsl:for-each select="example">
          <xsl:text>.</xsl:text>
          <xsl:value-of select="summary"/>
          <xsl:call-template name="newline"/>
          <xsl:text>==========================</xsl:text>
          <xsl:call-template name="newline"/>

          <xsl:apply-templates select="description"/>
          <xsl:call-template name="newline"/>

          <xsl:text>.Client</xsl:text>
          <xsl:call-template name="newline"/>
          <xsl:for-each select="request/*">
            <xsl:text>[source,xml]</xsl:text>
            <xsl:call-template name="newline"/>
            <xsl:text>----</xsl:text>
            <xsl:call-template name="newline"/>

            <xsl:call-template name="pretty"/>

            <xsl:call-template name="newline"/>
            <xsl:text>----</xsl:text>
            <xsl:call-template name="newline"/>
            <xsl:call-template name="newline"/>
          </xsl:for-each>

          <xsl:text>.Manager</xsl:text>
          <xsl:call-template name="newline"/>
          <xsl:for-each select="response/*">
            <xsl:text>[source,xml]</xsl:text>
            <xsl:call-template name="newline"/>
            <xsl:text>----</xsl:text>
            <xsl:call-template name="newline"/>

            <xsl:call-template name="pretty"/>

            <xsl:call-template name="newline"/>
            <xsl:text>----</xsl:text>
            <xsl:call-template name="newline"/>
          </xsl:for-each>
          <xsl:text>==========================</xsl:text>
          <xsl:call-template name="newline"/>
          <xsl:call-template name="newline"/>
        </xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="command" mode="index">
    <tr id="index">
      <td id="index"><a href="#command_{name}"><xsl:value-of select="name"/></a></td>
      <td id="index"><div style="margin-left: 15px;"><xsl:value-of select="normalize-space(summary)"/>.</div></td>
    </tr>
  </xsl:template>

  <xsl:template name="command-summary">
    <h2 id="command_summary">3 Summary of Commands</h2>
    <table id="index">
    <xsl:apply-templates select="command" mode="index"/>
    </table>
  </xsl:template>

  <xsl:template name="command-details">
    <xsl:text>=== Commands</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:apply-templates select="command"/>
  </xsl:template>

  <!-- Filter keywords -->
  <xsl:template match="filter_keywords">
    <xsl:param name="depth">0</xsl:param>

    <xsl:call-template name="bullet">
      <xsl:with-param name="depth" select="$depth + 1"/>
    </xsl:call-template>

    <xsl:text>_Keywords</xsl:text>
    <xsl:if test="condition">
      <xsl:text> if </xsl:text>
      <xsl:value-of select="condition"/>
    </xsl:if>
    <xsl:text>_</xsl:text>
    <xsl:call-template name="newline"/>

    <xsl:for-each select="column|option">
      <xsl:call-template name="bullet">
        <xsl:with-param name="depth" select="$depth + 2"/>
      </xsl:call-template>

      <xsl:text>_</xsl:text>
      <xsl:value-of select="name()"/>
      <xsl:text>_ *</xsl:text>
      <xsl:value-of select="name"/>
      <xsl:text>* (</xsl:text>
      <xsl:apply-templates select="type"/>
      <xsl:text>) </xsl:text>
      <xsl:value-of select="summary"/>
      <xsl:call-template name="newline"/>
    </xsl:for-each>
  </xsl:template>

  <!-- Changes. -->

  <xsl:template match="change">
    <xsl:param name="index">8.<xsl:value-of select="position()"/></xsl:param>
    <div>
      <div>
        <h3>
          <xsl:value-of select="$index"/>
          Change in <tt><xsl:value-of select="command"/></tt>
        </h3>
      </div>

      <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>

      <xsl:apply-templates select="description"/>
    </div>
  </xsl:template>

  <xsl:template name="changes">
    <h2 id="changes">
      8 Compatibility Changes in Version
      <xsl:value-of select="/protocol/version"/>
    </h2>
    <xsl:apply-templates select="change[version=/protocol/version]"/>
  </xsl:template>

  <!-- Deprecation Warnings. -->

  <xsl:template match="deprecation">
    <xsl:param name="index">9.<xsl:value-of select="position()"/></xsl:param>
    <div>
      <div>
        <h3>
          <xsl:value-of select="$index"/>
          Deprecation warning for <tt><xsl:value-of select="command"/></tt>
        </h3>
      </div>

      <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>

      <xsl:apply-templates select="description"/>
    </div>
  </xsl:template>

  <xsl:template name="deprecations">
    <h2 id="deprecations">
      9 Deprecation Warnings for Version
      <xsl:value-of select="/protocol/version"/>
    </h2>
    <xsl:apply-templates select="deprecation[version=/protocol/version]"/>
  </xsl:template>

  <!-- Root. -->

  <xsl:template match="protocol">
    <xsl:if test="abbreviation">
      <xsl:value-of select="abbreviation"/>
      <xsl:text>: </xsl:text>
    </xsl:if>
    <xsl:value-of select="name"/>
    <xsl:call-template name="newline"/>
    <xsl:text>==</xsl:text>
    <xsl:for-each select="str:tokenize(name, '')">
      <xsl:text>=</xsl:text>
    </xsl:for-each>
    <xsl:if test="abbreviation">
      <xsl:for-each select="str:tokenize(abbreviation, '')">
        <xsl:text>=</xsl:text>
      </xsl:for-each>
    </xsl:if>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>

    <xsl:if test="version">
      <xsl:text>Version </xsl:text>
      <xsl:value-of select="normalize-space(version)"/>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="newline"/>
    </xsl:if>

    <xsl:if test="summary">
      <xsl:value-of select="normalize-space(summary)"/>.
      <xsl:call-template name="newline"/>
      <xsl:call-template name="newline"/>
    </xsl:if>

    <xsl:call-template name="type-details"/>
    <xsl:call-template name="element-details"/>
    <xsl:call-template name="command-details"/>

<!--
    <xsl:call-template name="type-summary"/>
    <xsl:call-template name="element-summary"/>
                <xsl:call-template name="command-summary"/>
                <xsl:call-template name="rnc-preamble"/>
                <xsl:call-template name="command-details"/>
                <xsl:call-template name="changes"/>
                <xsl:call-template name="deprecations"/>
-->
  </xsl:template>

  <xsl:template match="/">
    <xsl:apply-templates select="protocol"/>
  </xsl:template>

</xsl:stylesheet>
