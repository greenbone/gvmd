<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Generate SQL (SQLite compatible) queries to update
the DFN-CERT tables of the CERT database.

Authors:
Timo Pollmeier <timo.pollmeier@greenbone.net>

Copyright:
Copyright (C) 2013 Greenbone Networks GmbH

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
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:dfncert="http://www.dfn-cert.de/dfncert.dtd"
  xmlns:atom="http://www.w3.org/2005/Atom"
  xmlns:str="http://exslt.org/strings"
  xmlns:date="http://exslt.org/dates-and-times"
  extension-element-prefixes="str date"
  >
  <xsl:output method="text"/>
  <xsl:param name="refdate" select="'0'"/>

  <xsl:template match="/">
  BEGIN TRANSACTION;
  <xsl:apply-templates select="atom:feed/atom:entry"/>
  COMMIT;
  </xsl:template>

  <xsl:template match="atom:entry">
  <xsl:choose>
  <xsl:when test="floor (date:seconds (atom:updated)) &gt; number($refdate)">
  INSERT OR REPLACE INTO dfn_cert_advs (
    uuid,
    name,
    comment,
    creation_time,
    modification_time,
    title,
    summary,
    cve_refs
  ) VALUES (
    "<xsl:value-of select="dfncert:refnum"/>",
    "<xsl:value-of select="dfncert:refnum"/>",
    "",
    <xsl:value-of select="floor (date:seconds (atom:published/text()))"/>,
    <xsl:value-of select="floor (date:seconds (atom:updated/text()))"/>,
    "<xsl:value-of select="str:replace(atom:title/text(), '&quot;', '&quot;&quot;')"/>",
    "<xsl:value-of select="str:replace(atom:summary/text(), '&quot;', '&quot;&quot;')"/>",
    <xsl:value-of select="count(dfncert:cve)"/>
  );
  <xsl:for-each select="dfncert:cve">
  INSERT OR REPLACE INTO dfn_cert_cves (
    adv_id,
    cve_name
  ) VALUES (
    (SELECT id FROM dfn_cert_advs WHERE name = "<xsl:value-of select="../dfncert:refnum"/>"),
    "<xsl:value-of select="."/>"
  );
  </xsl:for-each>
  </xsl:when>
  <xsl:otherwise>
  /* filtered entry dated <xsl:value-of select="atom:updated/text()"/> */
  </xsl:otherwise>
  </xsl:choose>
  </xsl:template>
</xsl:stylesheet>