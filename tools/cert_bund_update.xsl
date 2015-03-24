<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Generate SQL (SQLite compatible) queries to update
the CERT-Bund tables of the CERT database.

Authors:
Timo Pollmeier <timo.pollmeier@greenbone.net>

Copyright:
Copyright (C) 2014 Greenbone Networks GmbH

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
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:cb="http://www.cert-bund.de"
  xmlns:str="http://exslt.org/strings"
  xmlns:date="http://exslt.org/dates-and-times"
  extension-element-prefixes="str date"
  >
  <xsl:output method="text"/>
  <xsl:param name="refdate" select="'0'"/>

  <xsl:template match="/">
  BEGIN TRANSACTION;
  <xsl:apply-templates select="Advisories"/>
  COMMIT;
  </xsl:template>

  <xsl:template match="Advisory">
  <xsl:choose>
  <xsl:when test="floor (date:seconds (str:replace (Date, ' ', 'T'))) &gt;= number($refdate)">
  INSERT OR REPLACE INTO cert_bund_advs (
    uuid,
    name,
    comment,
    creation_time,
    modification_time,
    title,
    summary,
    cve_refs
  ) VALUES (
    "<xsl:value-of select="Ref_Num"/>",
    "<xsl:value-of select="Ref_Num"/>",
    "",
    <xsl:value-of select="floor (date:seconds (str:replace (Date, ' ', 'T')))"/>,
    <xsl:value-of select="floor (date:seconds (str:replace (Date, ' ', 'T')))"/>,
    "<xsl:value-of select="str:replace(Title/text(), '&quot;', '&quot;&quot;')"/>",
    "<xsl:for-each select="Description/Element/TextBlock">
      <xsl:value-of select="str:replace(text(), '&quot;', '&quot;&quot;')"/>
      <xsl:if test="position() != last()"><xsl:text> </xsl:text></xsl:if>
     </xsl:for-each>",
    <xsl:value-of select="count(CVEList/CVE)"/>
  );
  <xsl:for-each select="CVEList/CVE">
  INSERT OR REPLACE INTO cert_bund_cves (
    adv_id,
    cve_name
  ) VALUES (
    (SELECT id FROM cert_bund_advs WHERE name = "<xsl:value-of select="../../Ref_Num"/>"),
     "<xsl:value-of select="."/>"
  );
  </xsl:for-each>
  </xsl:when>
  <xsl:otherwise>
  /* filtered entry dated <xsl:value-of select="Date"/> */
  </xsl:otherwise>
  </xsl:choose>
  </xsl:template>
</xsl:stylesheet>