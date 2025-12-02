<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:func = "http://exslt.org/functions"
    extension-element-prefixes="str func">

<!--
Copyright (C) 2010-2022 Greenbone AG

SPDX-License-Identifier: AGPL-3.0-or-later
-->

<!-- Greenbone Management Protocol (GMP) single page HTML doc generator. -->

  <xsl:template match="command">
    <command>
      <name><xsl:value-of select="name"/></name>
      <summary><xsl:value-of select="summary"/></summary>
    </command>
  </xsl:template>

  <!-- Root. -->

  <xsl:template match="protocol">
    <protocol>
      <name><xsl:value-of select="name"/></name>
      <abbreviation><xsl:value-of select="abbreviation"/></abbreviation>
      <summary><xsl:value-of select="summary"/></summary>
      <version><xsl:value-of select="version"/></version>
      <xsl:apply-templates select="command"/>
    </protocol>
  </xsl:template>

  <xsl:template match="/">
    <xsl:apply-templates select="protocol"/>
  </xsl:template>

</xsl:stylesheet>
