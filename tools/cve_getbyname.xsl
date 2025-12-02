<?xml version="1.0" encoding="UTF-8"?>
<!--
Copyright (C) 2011-2022 Greenbone AG

SPDX-License-Identifier: AGPL-3.0-or-later
-->

<!-- Select a CVE item by name. -->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4"
  xmlns:cpe-lang="http://cpe.mitre.org/language/2.0"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:cve="http://scap.nist.gov/schema/feed/vulnerability/2.0"
  xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:patch="http://scap.nist.gov/schema/patch/0.1">

<xsl:output method="html"/>

<xsl:template match="cve:nvd">
  <xsl:copy-of select="cve:entry[@id = $refname]"/>
</xsl:template>

</xsl:stylesheet>

