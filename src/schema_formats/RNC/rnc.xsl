<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    extension-element-prefixes="str">
  <xsl:strip-space elements="*"/>

<!--
OpenVAS Manager
$Id$
Description: OpenVAS Manager Protocol (OMP) RNC support templates.

Authors:
Matthew Mundell <matthew.mundell@intevation.de>

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

  <!-- Commands. -->

  <xsl:template name="rnc-type">
    <xsl:choose>
      <xsl:when test="count (alts) &gt; 0">
        <xsl:for-each select="alts/alt">
          <xsl:choose>
            <xsl:when test="following-sibling::alt and preceding-sibling::alt">
              <xsl:text>|</xsl:text>
              <xsl:value-of select="."/>
            </xsl:when>
            <xsl:when test="count (following-sibling::alt) = 0">
              <xsl:text>|</xsl:text>
              <xsl:value-of select="."/>
              <xsl:text>" }</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:text>xsd:token { pattern = "</xsl:text>
              <xsl:value-of select="."/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="normalize-space(text())"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="attrib" match="attrib">
    <xsl:if test="($rnc-comments = 1) and summary">
      <xsl:text># </xsl:text>
      <xsl:value-of select="normalize-space(summary)"/>
      <xsl:text>.</xsl:text>
      <xsl:call-template name="newline"/>
      <xsl:text>       </xsl:text>
    </xsl:if>
    <xsl:text>attribute </xsl:text>
    <xsl:value-of select="name"/>
    <xsl:text> { </xsl:text>
    <xsl:for-each select="type">
      <xsl:call-template name="rnc-type"/>
    </xsl:for-each>
    <xsl:text> }</xsl:text>
    <xsl:choose>
      <xsl:when test="required=1"></xsl:when>
      <xsl:otherwise><xsl:text>?</xsl:text></xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="c" match="c">
    <xsl:value-of select="text()"/>
  </xsl:template>

  <xsl:template name="e" match="e">
    <xsl:param name="parent-name"/>
    <xsl:value-of select="$parent-name"/>
    <xsl:value-of select="text()"/>
  </xsl:template>

  <xsl:template name="r" match="r">
    <xsl:param name="parent-name"/>
    <xsl:value-of select="text()"/>
    <xsl:text>_response</xsl:text>
  </xsl:template>

  <xsl:template name="t" match="t">
    <xsl:choose>
      <xsl:when test="count (alts) &gt; 0">
        <xsl:for-each select="alts/alt">
          <xsl:choose>
            <xsl:when test="following-sibling::alt and preceding-sibling::alt">
              <xsl:text>|</xsl:text>
              <xsl:value-of select="."/>
            </xsl:when>
            <xsl:when test="count (following-sibling::alt) = 0">
              <xsl:text>|</xsl:text>
              <xsl:value-of select="."/>
              <xsl:text>" }</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:text>xsd:token { pattern = "</xsl:text>
              <xsl:value-of select="."/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="normalize-space(text())"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="pattern-part">
    <xsl:param name="parent-name"/>
    <xsl:choose>
      <xsl:when test="name()='any'">
        <xsl:for-each select="*">
          <xsl:call-template name="pattern-part">
            <xsl:with-param name="parent-name" select="$parent-name"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:text>*</xsl:text>
      </xsl:when>
      <xsl:when test="name()='attrib'">
        <xsl:call-template name="attrib"/>
      </xsl:when>
      <xsl:when test="name()='c'">
        <xsl:call-template name="c"/>
      </xsl:when>
      <xsl:when test="name()='e'">
        <xsl:call-template name="e">
          <xsl:with-param name="parent-name" select="$parent-name"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="name()='g'">
        <xsl:text>( </xsl:text>
        <xsl:for-each select="*">
          <xsl:choose>
            <xsl:when test="preceding-sibling::*">
              <xsl:text>           &amp; </xsl:text>
            </xsl:when>
            <xsl:otherwise>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:call-template name="pattern-part">
            <xsl:with-param name="parent-name" select="$parent-name"/>
          </xsl:call-template>
          <xsl:if test="following-sibling::*">
            <xsl:call-template name="newline"/>
          </xsl:if>
        </xsl:for-each>
        <xsl:text> )</xsl:text>
      </xsl:when>
      <xsl:when test="name()='o'">
        <xsl:for-each select="*">
          <xsl:call-template name="pattern-part">
            <xsl:with-param name="parent-name" select="$parent-name"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:text>?</xsl:text>
      </xsl:when>
      <xsl:when test="name()='or'">
        <xsl:text>( </xsl:text>
        <xsl:for-each select="*">
          <xsl:choose>
            <xsl:when test="preceding-sibling::*">
              <xsl:text>           | </xsl:text>
            </xsl:when>
            <xsl:otherwise>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:call-template name="pattern-part">
            <xsl:with-param name="parent-name" select="$parent-name"/>
          </xsl:call-template>
          <xsl:if test="following-sibling::*">
            <xsl:call-template name="newline"/>
          </xsl:if>
        </xsl:for-each>
        <xsl:text> )</xsl:text>
      </xsl:when>
      <xsl:when test="name()='r'">
        <xsl:call-template name="r">
          <xsl:with-param name="parent-name" select="$parent-name"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="name()='t'">
      </xsl:when>
      <xsl:otherwise>
        ERROR
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="pattern" match="pattern">
    <xsl:param name="parent-name"/>
    <xsl:choose>
      <xsl:when test="(count (t) = 0) and (string-length (normalize-space (text ())) = 0)">
        <xsl:text>       ""</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="count (t) = 0">
        <xsl:text>       </xsl:text>
        <xsl:value-of select="normalize-space (text ())"/>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>       </xsl:text>
        <!-- There should be only one t. -->
        <xsl:for-each select="t">
          <xsl:call-template name="t"/>
          <xsl:call-template name="newline"/>
        </xsl:for-each>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:for-each select="*[name()!='t']">
      <xsl:choose>
        <xsl:when test="preceding-sibling::*">
          <xsl:text>       &amp; </xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:text>       &amp; </xsl:text>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:call-template name="pattern-part">
        <xsl:with-param name="parent-name" select="$parent-name"/>
      </xsl:call-template>
      <xsl:call-template name="newline"/>
    </xsl:for-each>
  </xsl:template>

  <xsl:template name="ele">
    <xsl:param name="parent-name"/>
    <xsl:if test="($rnc-comments = 1) and summary">
      <xsl:text># </xsl:text>
      <xsl:value-of select="normalize-space(summary)"/>
      <xsl:text>.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:call-template name="command-body">
      <xsl:with-param name="parent-name" select="$parent-name"/>
    </xsl:call-template>
  </xsl:template>

  <xsl:template name="command-body">
    <xsl:param name="parent-name"/>
    <xsl:variable name="command-name" select="concat ($parent-name, name)"/>
    <xsl:value-of select="$command-name"/>
    <xsl:call-template name="newline"/>
    <xsl:text> = element </xsl:text>
    <xsl:value-of select="name"/>
    <xsl:call-template name="newline"/>
    <xsl:text>     {</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="pattern">
      <xsl:call-template name="pattern">
        <xsl:with-param name="parent-name" select="concat ($command-name, '_')"/>
      </xsl:call-template>
    </xsl:for-each>
    <xsl:text>     }</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="ele">
      <xsl:call-template name="newline"/>
      <xsl:call-template name="ele">
        <xsl:with-param name="parent-name" select="concat ($command-name, '_')"/>
      </xsl:call-template>
    </xsl:for-each>
  </xsl:template>

  <!-- Responses. -->

  <xsl:template name="response-body">
    <xsl:variable name="command-name" select="concat (name, '_response')"/>
    <xsl:value-of select="$command-name"/>
    <xsl:call-template name="newline"/>
    <xsl:text> = element </xsl:text>
    <xsl:value-of select="$command-name"/>
    <xsl:call-template name="newline"/>
    <xsl:text>     {</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="response/pattern">
      <xsl:call-template name="pattern">
        <xsl:with-param name="parent-name" select="concat ($command-name, '_')"/>
      </xsl:call-template>
    </xsl:for-each>
    <xsl:text>     }</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="response/ele">
      <xsl:call-template name="newline"/>
      <xsl:call-template name="ele">
        <xsl:with-param name="parent-name" select="concat ($command-name, '_')"/>
      </xsl:call-template>
    </xsl:for-each>
  </xsl:template>

</xsl:stylesheet>
