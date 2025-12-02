<?xml version="1.0" encoding="UTF-8"?>
<!--
Copyright (C) 2013-2022 Greenbone AG

SPDX-License-Identifier: AGPL-3.0-or-later
-->

<!-- Select a DFN-CERT item by name. -->

<xsl:stylesheet version="1.0" 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:str="http://exslt.org/strings"
  xmlns:dfncert="http://www.dfn-cert.de/dfncert.dtd"
  xmlns:atom="http://www.w3.org/2005/Atom"
  extension-element-prefixes="str"
  >

<xsl:output method="html"/>

<xsl:template match="/">
  <xsl:copy-of select="//atom:entry[dfncert:refnum = $refname]"/>
</xsl:template>

</xsl:stylesheet>

