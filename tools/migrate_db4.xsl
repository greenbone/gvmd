<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Migrate the scap db from version 3 to 4
database.

Authors:
Andre Heinecke <andre.heinecke@greenbone.net>

Copyright:
Copyright (C) 2012 Greenbone Networks GmbH

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
  xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4"
  xmlns:cpe-lang="http://cpe.mitre.org/language/2.0"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:cve="http://scap.nist.gov/schema/feed/vulnerability/2.0"
  xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2"
  xmlns:str="http://exslt.org/strings"
  extension-element-prefixes="str"
  >
<xsl:output method="text"/>

<xsl:template match="cve:entry">
  UPDATE cves SET 
  vector = '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:access-vector"/>',
  complexity = '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:access-complexity"/>',
  authentication = '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:authentication"/>',
  confidentiality_impact = '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:confidentiality-impact"/>',
  integrity_impact = '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:integrity-impact"/>',
  availability_impact = '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:availability-impact"/>',
  products =
   '<xsl:for-each select="vuln:vulnerable-software-list/vuln:product">
    <xsl:value-of select='str:replace(str:replace(
      str:decode-uri(text()), "%7E", "~"),
      "&#39;", "&#39;&#39;")'/>
    <xsl:text> </xsl:text>
  </xsl:for-each>'
  where name = '<xsl:value-of select="@id"/>';
</xsl:template>

<xsl:template match="/">
BEGIN TRANSACTION;
  <xsl:apply-templates/>
COMMIT;
</xsl:template>

</xsl:stylesheet>

