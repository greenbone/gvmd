<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    extension-element-prefixes="str">
  <xsl:output method="text" encoding="string" indent="no"/>
  <xsl:strip-space elements="*"/>

<!--
OpenVAS Manager
$Id$
Description: OpenVAS Manager Protocol (OMP) RNC generator.

Authors:
Matthew Mundell <matthew.mundell@greenbone.net>

Copyright:
Copyright (C) 2010 Greenbone Networks GmbH

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

  <xsl:variable name="rnc-comments">1</xsl:variable>
  <xsl:include href="rnc.xsl"/>

  <!-- Helpers. -->

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

  <!-- Data types. -->

  <xsl:template name="types">
    <xsl:text>### Data Types</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="type">
      <xsl:if test="($rnc-comments = 1) and summary">
        <xsl:text># </xsl:text>
        <xsl:value-of select="summary"/>
        <xsl:text>.</xsl:text>
      </xsl:if>
      <xsl:call-template name="newline"/>
      <xsl:value-of select="name"/>
      <xsl:text> = </xsl:text>
      <xsl:value-of select="normalize-space (pattern)"/>
      <xsl:call-template name="newline"/>
    </xsl:for-each>
  </xsl:template>

  <!-- Elements. -->

  <xsl:template name="elements">
    <xsl:text>### Element Types</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="element">
      <xsl:call-template name="newline"/>
      <xsl:text>## Element Type </xsl:text>
      <xsl:value-of select="name"/>
      <xsl:call-template name="newline"/>
      <xsl:if test="($rnc-comments = 1) and summary">
        <xsl:text>##</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>## </xsl:text>
        <xsl:value-of select="summary"/>
        <xsl:text>.</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:if>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="command-body"/>
    </xsl:for-each>
  </xsl:template>

  <!-- Commands. -->

  <xsl:template name="commands">
    <xsl:text>### Commands</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="command">
      <xsl:call-template name="newline"/>
      <xsl:text>## Command </xsl:text>
      <xsl:value-of select="name"/>
      <xsl:call-template name="newline"/>
      <xsl:if test="($rnc-comments = 1) and summary">
        <xsl:text>##</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>## </xsl:text>
        <xsl:value-of select="summary"/>
        <xsl:text>.</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:if>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="command-body"/>
    </xsl:for-each>
  </xsl:template>

  <!-- Responses. -->

  <xsl:template name="responses">
    <xsl:text>### Responses</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="command">
      <xsl:call-template name="newline"/>
      <xsl:text>## Response to </xsl:text>
      <xsl:value-of select="name"/>
      <xsl:call-template name="newline"/>
      <xsl:if test="($rnc-comments = 1) and response/summary">
        <xsl:text>#</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text># </xsl:text>
        <xsl:value-of select="summary"/>
        <xsl:text>.</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:if>
      <xsl:call-template name="newline"/>
      <xsl:call-template name="response-body"/>
    </xsl:for-each>
  </xsl:template>

  <!-- Root. -->

  <xsl:template match="protocol">
    <xsl:if test="name">
      <xsl:text>#### </xsl:text>
      <xsl:value-of select="name"/>
      <xsl:if test="abbreviation">
        <xsl:text> (</xsl:text>
        <xsl:value-of select="abbreviation"/>
        <xsl:text>)</xsl:text>
      </xsl:if>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:if test="version">
      <xsl:text>####</xsl:text>
      <xsl:call-template name="newline"/>
      <xsl:text>#### Version: </xsl:text>
      <xsl:value-of select="version"/>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:choose>
      <xsl:when test="($rnc-comments = 1) and summary">
        <xsl:text>####</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:text>#### </xsl:text>
        <xsl:value-of select="summary"/>
        <xsl:text>.</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="name">
        <xsl:call-template name="newline"/>
      </xsl:when>
    </xsl:choose>
    <xsl:call-template name="preamble"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="types"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="elements"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="commands"/>
    <xsl:call-template name="newline"/>
    <xsl:call-template name="responses"/>
  </xsl:template>

  <xsl:template match="/">
    <xsl:apply-templates select="protocol"/>
  </xsl:template>

</xsl:stylesheet>
