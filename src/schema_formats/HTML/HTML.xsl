<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:func = "http://exslt.org/functions"
    extension-element-prefixes="str func">
  <xsl:output method="html"
              doctype-system="http://www.w3.org/TR/html4/strict.dtd"
              doctype-public="-//W3C//DTD HTML 4.01//EN"
              encoding="UTF-8" />
  <xsl:strip-space elements="pretty"/>

<!--
Copyright (C) 2010-2022 Greenbone AG

SPDX-License-Identifier: AGPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->

<!-- Greenbone Management Protocol (GMP) single page HTML doc generator. -->

  <xsl:variable name="rnc-comments">0</xsl:variable>
  <xsl:include href="../rnc.xsl"/>

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

  <xsl:template name="description-more-details">
    <xsl:param name="descr"/>
    <xsl:choose>
      <xsl:when test="(count($descr/*) = 0) and (string-length(normalize-space($descr/text())) &gt; 0)">
        <div><xsl:value-of select="$descr/text()"/></div>
      </xsl:when>
      <xsl:otherwise>
        <xsl:for-each select="$descr/*">
          <xsl:choose>
            <xsl:when test="name()='p'">
              <div><xsl:value-of select="text()"/></div>
            </xsl:when>
            <xsl:when test="name()='l'">
              <div>
                <xsl:value-of select="lh"/>
                <ul>
                  <xsl:for-each select="li">
                    <li><xsl:value-of select="text()"/></li>
                  </xsl:for-each>
                </ul>
                <xsl:value-of select="lf"/>
              </div>
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
          <xsl:when test="name() = 'help_response' or name() = 'p' or name() = 'icalendar'">
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

  <xsl:template name="details-summary-2">
    <xsl:param name="id"/>
    <xsl:param name="text"/>
    <summary id="{$id}"
             style="margin-block-start: .83em; margin-block-end: .83em; cursor: pointer;">
      <h2 style="display: inline;"><xsl:value-of select="$text"/></h2>
    </summary>
  </xsl:template>

  <xsl:template name="details-summary-3">
    <xsl:param name="id"/>
    <xsl:param name="name"/>
    <xsl:param name="text"/>
    <summary id="{$id}"
             style="margin-block-start: .83em; margin-block-end: .83em; cursor: pointer;">
      <h3 style="display: inline;"><xsl:value-of select="$text"/> <tt><xsl:value-of select="$name"/></tt></h3>
    </summary>
  </xsl:template>

  <xsl:template name="details-summary-4">
    <xsl:param name="text"/>
    <summary style="margin-block-start: .83em; margin-block-end: .83em; cursor: pointer;">
      <h4 style="display: inline;"><xsl:value-of select="$text"/></h4>
    </summary>
  </xsl:template>

  <!-- RNC preamble. -->

  <xsl:template name="rnc-preamble">
    <details>
      <xsl:call-template name="details-summary-2">
        <xsl:with-param name="id" select="'rnc_preamble'"/>
        <xsl:with-param name="text" select="'4 RNC Preamble'"/>
      </xsl:call-template>
      <div style="border: 1px solid; padding:10px; width: 85%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
        <pre>
          <xsl:call-template name="preamble"/>
        </pre>
      </div>
    </details>
  </xsl:template>

  <!-- Types. -->

  <xsl:template match="type" mode="index">
    <tr id="index">
      <td id="index"><a href="#type_{name}"><xsl:value-of select="name"/></a></td>
      <td id="index">
        <xsl:if test="summary">
          <div style="margin-left: 15px;"><xsl:value-of select="normalize-space(summary)"/>.</div>
        </xsl:if>
      </td>
    </tr>
  </xsl:template>

  <xsl:template name="type-summary">
    <details open="">
      <xsl:call-template name="details-summary-2">
        <xsl:with-param name="id" select="'type_summary'"/>
        <xsl:with-param name="text" select="'1 Summary of Data Types'"/>
      </xsl:call-template>
      <table id="index">
        <xsl:apply-templates select="type" mode="index"/>
      </table>
    </details>
  </xsl:template>

  <xsl:template match="type" mode="details">
    <xsl:param name="index">5.<xsl:value-of select="position()"/></xsl:param>
    <details open="">
      <xsl:call-template name="details-summary-3">
        <xsl:with-param name="id" select="concat('type_', name)"/>
        <xsl:with-param name="text" select="concat($index, ' Data Type ')"/>
        <xsl:with-param name="name" select="name"/>
      </xsl:call-template>

      <xsl:if test="summary">
        <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>
      </xsl:if>

      <xsl:apply-templates select="description"/>

      <details>
        <xsl:call-template name="details-summary-4">
          <xsl:with-param name="text" select="concat($index, '.1 RNC')"/>
        </xsl:call-template>

        <div style="border: 1px solid; padding:10px; width: 85%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
          <pre>
            <xsl:value-of select="name"/>
            <xsl:text> = </xsl:text>
            <xsl:call-template name="wrap">
              <xsl:with-param name="string">
                <xsl:value-of select="normalize-space (pattern)"/>
              </xsl:with-param>
            </xsl:call-template>
            <xsl:call-template name="newline"/>
          </pre>
        </div>
      </details>

    </details>
  </xsl:template>

  <xsl:template name="type-details">
    <details open="">
      <xsl:call-template name="details-summary-2">
        <xsl:with-param name="id" select="'type_details'"/>
        <xsl:with-param name="text" select="'5 Data Type Details'"/>
      </xsl:call-template>
      <xsl:apply-templates select="type" mode="details"/>
    </details>
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
    <details open="">
      <xsl:call-template name="details-summary-2">
        <xsl:with-param name="id" select="'element_summary'"/>
        <xsl:with-param name="text" select="'2 Summary of Elements'"/>
      </xsl:call-template>
      <table id="index">
        <xsl:apply-templates select="element" mode="index"/>
      </table>
    </details>
  </xsl:template>

  <xsl:template name="element-details">
    <details open="">
      <xsl:call-template name="details-summary-2">
        <xsl:with-param name="id" select="'element_details'"/>
        <xsl:with-param name="text" select="'6 Element Details'"/>
      </xsl:call-template>
      <xsl:apply-templates select="element"/>
    </details>
  </xsl:template>

  <xsl:template match="element">
    <xsl:param name="index">6.<xsl:value-of select="position()"/></xsl:param>
    <details open="">
      <xsl:call-template name="details-summary-3">
        <xsl:with-param name="id" select="concat('element_', name)"/>
        <xsl:with-param name="text" select="concat($index, ' Element ')"/>
        <xsl:with-param name="name" select="name"/>
      </xsl:call-template>

      <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>

      <xsl:apply-templates select="description"/>

      <details open="">
        <xsl:call-template name="details-summary-4">
          <xsl:with-param name="text" select="concat($index, '.1 Structure')"/>
        </xsl:call-template>

        <ul style="list-style: none">
          <li>
            <xsl:call-template name="command-structure"/>
          </li>
        </ul>
      </details>

      <details>
        <xsl:call-template name="details-summary-4">
          <xsl:with-param name="text" select="concat($index, '.2 RNC')"/>
        </xsl:call-template>

        <div style="border: 1px solid; padding:10px; width: 85%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
          <div style="margin-left: 5%">
            <xsl:call-template name="command-relax"/>
          </div>
        </div>
      </details>

    </details>
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
    <xsl:param name="line-element"/>
    <xsl:param name="element-suffix"/>
    <xsl:choose>
      <xsl:when test="name() = 'alts'">
        <xsl:text>One of: </xsl:text>
        <xsl:for-each select="*">
          <xsl:if test="name() = 'alt'">
            <div style="margin-left: 15px">
              <xsl:value-of select="normalize-space(.)"/>
            </div>
          </xsl:if>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'any'">
        <xsl:for-each select="*">
          <xsl:call-template name="structure-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="element-suffix" select="'*'"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'attrib'">
        <li>
          @<b><xsl:value-of select="name"/></b>
          (<xsl:apply-templates select="type"/>)
          <xsl:if test="summary">
            <xsl:value-of select="normalize-space(summary)"/>.
          </xsl:if>
          <xsl:apply-templates select="filter_keywords"/>
          <xsl:if test="description">
            <div style="margin-left: 10px; padding: 0 0 3px 5px;">
              <i>More Details</i>
              <div style="margin-left: 10px; padding-left: 10px;">
                <xsl:call-template name="description-more-details">
                  <xsl:with-param name="descr" select="description"/>
                </xsl:call-template>
              </div>
            </div>
          </xsl:if>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'c'">
        <li>
          <xsl:variable name="element-name" select="text()"/>
          &lt;<b><xsl:value-of select="text()"/>&gt;</b>
          <xsl:value-of select="$element-suffix"/>
          <div style="margin-left: 15px; display: inline;">
            <a href="#command_{$element-name}"><xsl:value-of select="$element-name"/></a> command.
          </div>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'r'">
        <li>
          <xsl:variable name="element-name" select="text()"/>
          &lt;<b><xsl:value-of select="text()"/>_response&gt;</b>
          <xsl:value-of select="$element-suffix"/>
          <div style="margin-left: 15px; display: inline;">
            Response to <a href="#command_{$element-name}"><xsl:value-of select="$element-name"/></a> command.
          </div>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'e'">
        <li>
          <xsl:variable name="element-name" select="text()"/>
          <xsl:variable name="new-line-element"
                        select="$line-element/ele[name=$element-name]"/>
          <xsl:choose>
            <xsl:when test="$new-line-element">
              &lt;<b><xsl:value-of select="text()"/></b>&gt;
              <xsl:value-of select="$element-suffix"/>
              <xsl:if test="$new-line-element/type">
                <div style="margin-left: 15px; display: inline;">(<xsl:apply-templates select="$new-line-element/type" mode="element"/>)</div>
              </xsl:if>
              <xsl:if test="$new-line-element/summary">
                <div style="margin-left: 15px; display: inline;"><xsl:value-of select="normalize-space($new-line-element/summary)"/>.</div>
              </xsl:if>
              <ul style="list-style: none">
                <xsl:for-each select="$new-line-element/pattern/*">
                  <xsl:call-template name="structure-line">
                    <xsl:with-param name="line-element" select="$new-line-element"/>
                  </xsl:call-template>
                </xsl:for-each>
              </ul>
              <xsl:if test="$new-line-element/description">
                <div style="margin-left: 20px; padding: 0 0 3px 5px;">
                  <i>More Details</i>
                  <div style="margin-left: 10px; padding-left: 10px;">
                    <xsl:call-template name="description-more-details">
                      <xsl:with-param name="descr" select="$new-line-element/description"/>
                    </xsl:call-template>
                  </div>
                </div>
              </xsl:if>
            </xsl:when>
            <xsl:otherwise>
              <xsl:variable name="global-element"
                            select="/protocol/element[name=$element-name]"/>
              &lt;<a href="#element_{$global-element/name}"><b><xsl:value-of select="text()"/></b></a>&gt;
              <xsl:value-of select="$element-suffix"/>
              <div style="margin-left: 15px; display: inline;"><xsl:value-of select="normalize-space($global-element/summary)"/>.</div>
            </xsl:otherwise>
          </xsl:choose>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'g'">
        <li>
          <i>The group</i><b><xsl:value-of select="$element-suffix"/></b>
          <ul style="list-style: none">
            <xsl:for-each select="*">
              <xsl:call-template name="structure-line">
                <xsl:with-param name="line-element" select="$line-element"/>
              </xsl:call-template>
            </xsl:for-each>
          </ul>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'o'">
        <xsl:for-each select="*">
          <xsl:call-template name="structure-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="element-suffix" select="'?'"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'or'">
        <li>
          <i>One of</i><b><xsl:value-of select="$element-suffix"/></b>
          <ul style="list-style: none">
            <xsl:for-each select="*">
              <xsl:call-template name="structure-line">
                <xsl:with-param name="line-element" select="$line-element"/>
              </xsl:call-template>
            </xsl:for-each>
          </ul>
        </li>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="command-structure">
    <ul style="list-style: none">
      <xsl:choose>
        <xsl:when test="(count(pattern/*) = 0) and (string-length(normalize-space(pattern)) = 0)">
          <i>Empty single element.</i>
        </xsl:when>
        <xsl:otherwise>
          <xsl:variable name="command" select="."/>
          <xsl:for-each select="pattern/*">
            <xsl:call-template name="structure-line">
              <xsl:with-param name="line-element" select="$command"/>
            </xsl:call-template>
          </xsl:for-each>
        </xsl:otherwise>
      </xsl:choose>
    </ul>
  </xsl:template>

  <xsl:template match="command">
    <xsl:param name="index">7.<xsl:value-of select="position()"/></xsl:param>
    <details open="">
      <xsl:call-template name="details-summary-3">
        <xsl:with-param name="id" select="concat('command_', name)"/>
        <xsl:with-param name="text" select="concat($index, ' Command ')"/>
        <xsl:with-param name="name" select="name"/>
      </xsl:call-template>

      <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>

      <xsl:apply-templates select="description"/>

      <details open="">
        <xsl:call-template name="details-summary-4">
          <xsl:with-param name="text" select="concat($index, '.1 Structure')"/>
        </xsl:call-template>

        <ul style="list-style: none">
          <li>
            <i>Command</i>
            <xsl:call-template name="command-structure"/>
          </li>
          <li style="margin-top: 15px;">
            <i>Response</i>
            <xsl:for-each select="response">
              <xsl:call-template name="command-structure"/>
            </xsl:for-each>
          </li>
        </ul>
      </details>

      <details>
        <xsl:call-template name="details-summary-4">
          <xsl:with-param name="text" select="concat($index, '.2 RNC')"/>
        </xsl:call-template>

        <div style="border: 1px solid; padding:10px; width: 85%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
          <i>Command</i>
          <div style="margin-left: 5%">
            <xsl:call-template name="command-relax"/>
          </div>
          <i>Response</i>
          <div style="margin-left: 5%">
            <xsl:call-template name="response-relax"/>
          </div>
        </div>
      </details>

      <xsl:choose>
        <xsl:when test="count(example) &gt; 0">
          <xsl:for-each select="example">
            <details open="">
              <xsl:call-template name="details-summary-4">
                <xsl:with-param name="text" select="concat($index, '.3 Example: ', summary)"/>
              </xsl:call-template>

              <xsl:apply-templates select="description"/>
              <div style="margin-left: 5%; margin-right: 5%;">
                <i>Client</i>
                <div style="margin-left: 2%; margin-right: 2%;">
                  <xsl:for-each select="request/*">
                    <pre>
                      <xsl:call-template name="pretty"/>
                    </pre>
                  </xsl:for-each>
                </div>
                <i>Manager</i>
                <div style="margin-left: 2%; margin-right: 2%;">
                  <xsl:for-each select="response/*">
                    <pre>
                      <xsl:call-template name="pretty"/>
                    </pre>
                  </xsl:for-each>
                </div>
              </div>
            </details>
          </xsl:for-each>
        </xsl:when>
        <xsl:otherwise>
        </xsl:otherwise>
      </xsl:choose>

    </details>
  </xsl:template>

  <xsl:template match="command" mode="index">
    <tr id="index">
      <td id="index"><a href="#command_{name}"><xsl:value-of select="name"/></a></td>
      <td id="index"><div style="margin-left: 15px;"><xsl:value-of select="normalize-space(summary)"/>.</div></td>
    </tr>
  </xsl:template>

  <xsl:template name="command-summary">
    <details open="">
      <xsl:call-template name="details-summary-2">
        <xsl:with-param name="id" select="'command_summary'"/>
        <xsl:with-param name="text" select="'3 Summary of Commands'"/>
      </xsl:call-template>
      <table id="index">
        <xsl:apply-templates select="command" mode="index"/>
      </table>
    </details>
  </xsl:template>

  <xsl:template name="command-details">
    <details open="">
      <xsl:call-template name="details-summary-2">
        <xsl:with-param name="id" select="'command_details'"/>
        <xsl:with-param name="text" select="'7 Command Details'"/>
      </xsl:call-template>
      <xsl:apply-templates select="command"/>
    </details>
  </xsl:template>

  <!-- Filter keywords -->
  <xsl:template match="filter_keywords">
    <div style="margin-left: 10px; padding: 0 0 3px 5px">
      <i>
        <b>Keywords</b>
        <xsl:if test="condition">
          <xsl:text> if </xsl:text>
          <xsl:value-of select="condition"/>
        </xsl:if>
      </i>
      <ul style="list-style: none; padding-left: 10px;">
        <xsl:for-each select="column|option">
          <li>
            <i>
              <xsl:value-of select="name()"/>
              <xsl:text> </xsl:text>
            </i>
            <b><xsl:value-of select="name"/></b>
            <xsl:text> (</xsl:text>
              <xsl:apply-templates select="type"/>
            <xsl:text>) </xsl:text>
            <xsl:value-of select="summary"/>
          </li>
        </xsl:for-each>
      </ul>
    </div>
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
    <details open="">
      <xsl:call-template name="details-summary-2">
        <xsl:with-param name="id" select="'changes'"/>
        <xsl:with-param name="text">
          <xsl:value-of select="'8 Compatibility Changes in Version '"/>
          <xsl:value-of select="/protocol/version"/>
        </xsl:with-param>
      </xsl:call-template>
      <xsl:apply-templates select="change[version=/protocol/version]"/>
    </details>
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
    <xsl:if test="deprecation[version=/protocol/version]">
      <h2 id="deprecations">
        9 Deprecation Warnings for Version
        <xsl:value-of select="/protocol/version"/>
      </h2>
      <xsl:apply-templates select="deprecation[version=/protocol/version]"/>
    </xsl:if>
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

                <h2 id="contents">Contents</h2>
                <ol>
                  <li><a href="#type_summary">Summary of Data Types</a></li>
                  <li><a href="#element_summary">Summary of Elements</a></li>
                  <li><a href="#command_summary">Summary of Commands</a></li>
                  <li><a href="#rnc_preamble">RNC Preamble</a></li>
                  <li><a href="#type_details">Data Type Details</a></li>
                  <li><a href="#element_details">Element Details</a></li>
                  <li><a href="#command_details">Command Details</a></li>
                  <li>
                    <a href="#changes">
                      Compatibility Changes in Version
                      <xsl:value-of select="/protocol/version"/>
                    </a>
                  </li>
                  <xsl:if test="deprecation[version=/protocol/version]">
                    <li>
                      <a href="#deprecations">
                        Deprecation Warnings for Version
                        <xsl:value-of select="/protocol/version"/>
                      </a>
                    </li>
                  </xsl:if>
                </ol>

                <xsl:call-template name="type-summary"/>
                <xsl:call-template name="element-summary"/>
                <xsl:call-template name="command-summary"/>
                <xsl:call-template name="rnc-preamble"/>
                <xsl:call-template name="type-details"/>
                <xsl:call-template name="element-details"/>
                <xsl:call-template name="command-details"/>
                <xsl:call-template name="changes"/>
                <xsl:call-template name="deprecations"/>

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
