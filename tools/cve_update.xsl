<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Generate SQL (SQLite compatible) queries to update the CVE
database.

Authors:
Henri Doreau <henri.doreau@greenbone.net>

Copyright:
Copyright (C) 2011 Greenbone Networks GmbH

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
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4" xmlns:cpe-lang="http://cpe.mitre.org/language/2.0" xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1" xmlns:cve="http://scap.nist.gov/schema/feed/vulnerability/2.0" xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:patch="http://scap.nist.gov/schema/patch/0.1">

<xsl:output method="text"/>

<xsl:template match="cve:entry">
  <xsl:variable name="cvss">
    <xsl:choose>
      <xsl:when test="vuln:cvss/cvss:base_metrics/cvss:score/text()">
        <xsl:value-of select="number(vuln:cvss/cvss:base_metrics/cvss:score/text())"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="0"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>
  <xsl:variable name="cveid" select="@id"/>

INSERT OR REPLACE INTO cves (cve,last_mod,cvss,description) VALUES ("<xsl:value-of select="$cveid"/>","<xsl:value-of select="vuln:last-modified-datetime/text()"/>",<xsl:value-of select="$cvss"/>,"<xsl:value-of select="translate(vuln:summary/text(), '&quot;', '')"/>");
  <xsl:for-each select="vuln:vulnerable-software-list/vuln:product">
INSERT OR IGNORE INTO cpes (name) VALUES ("<xsl:value-of select="text()"/>");
INSERT OR REPLACE INTO affected_products (cve,cpe) VALUES ((SELECT id FROM cves WHERE cve="<xsl:value-of select="$cveid"/>"),(SELECT id FROM cpes WHERE name="<xsl:value-of select="text()"/>"));
  </xsl:for-each>
</xsl:template>

<xsl:template match="/">
BEGIN TRANSACTION;
  <xsl:apply-templates/>
COMMIT;
</xsl:template>

</xsl:stylesheet>

