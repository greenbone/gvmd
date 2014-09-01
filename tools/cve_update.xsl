<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Generate SQL (SQLite compatible) queries to update the CVE
database.

Authors:
Henri Doreau <henri.doreau@greenbone.net>
Timo Pollmeier <timo.pollmeier@greenbone.net>

Copyright:
Copyright (C) 2011, 2013 Greenbone Networks GmbH

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
  xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4"
  xmlns:cpe-lang="http://cpe.mitre.org/language/2.0"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:cve="http://scap.nist.gov/schema/feed/vulnerability/2.0"
  xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:str="http://exslt.org/strings"
  xmlns:patch="http://scap.nist.gov/schema/patch/0.1"
  extension-element-prefixes="str"
  >
<xsl:output method="text"/>

<xsl:template match="cve:entry">
  INSERT OR REPLACE INTO cves (
  uuid,
  name,
  creation_time,
  modification_time,
  cvss,
  description,
  vector,
  complexity,
  authentication,
  confidentiality_impact,
  integrity_impact,
  availability_impact,
  products) VALUES (
  '<xsl:value-of select="@id"/>',
  '<xsl:value-of select="@id"/>',
  strftime('%s', '<xsl:value-of select="vuln:published-datetime"/>'),
  strftime('%s', '<xsl:value-of select="vuln:last-modified-datetime"/>'),
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:score"/>',
  '<xsl:value-of select='str:replace(vuln:summary/text(), "&#39;", "&#39;&#39;")'/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:access-vector"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:access-complexity"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:authentication"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:confidentiality-impact"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:integrity-impact"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:availability-impact"/>',
  '<xsl:for-each select="vuln:vulnerable-software-list/vuln:product">
    <xsl:value-of select='str:replace(str:replace(
      str:decode-uri(text()), "%7E", "~"),
      "&#39;", "&#39;&#39;")'/>
    <xsl:text> </xsl:text>
  </xsl:for-each>');

  <xsl:for-each select="vuln:vulnerable-software-list/vuln:product">
    <xsl:variable name="decoded_cpe" select='
      str:replace(
      str:replace(
      str:decode-uri(text()), "%7E", "~"),
      "&#39;", "&#39;&#39;")'/>
  INSERT OR IGNORE INTO cpes (uuid, name) VALUES ('<xsl:value-of select="$decoded_cpe"/>', '<xsl:value-of select="$decoded_cpe"/>');

  INSERT OR REPLACE INTO affected_products (cve,cpe) VALUES ((SELECT id FROM cves WHERE uuid='<xsl:value-of select="../../@id"/>'),
  (SELECT id FROM cpes WHERE name='<xsl:value-of select="$decoded_cpe"/>'));
  </xsl:for-each>
</xsl:template>

<xsl:template match="/">
<!-- Activate delete triggers for replace -->
PRAGMA recursive_triggers='ON';
BEGIN TRANSACTION;
  <xsl:apply-templates/>
COMMIT;
</xsl:template>

</xsl:stylesheet>

