<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Select CPEs which have been updated after a certain date.

Authors:
Henri Doreau <henri.doreau@greenbone.net>

Copyright:
Copyright (C) 2011 Greenbone Networks GmbH

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
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.3" xmlns:meta="http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2" xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:config="http://scap.nist.gov/schema/configuration/0.1" xmlns:cpe="http://cpe.mitre.org/dictionary/2.0" xsi:schemaLocation="http://scap.nist.gov/schema/configuration/0.1 http://nvd.nist.gov/schema/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.3 http://nvd.nist.gov/schema/scap-core_0.3.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 http://nvd.nist.gov/schema/cpe-dictionary-metadata_0.2.xsd" xmlns:date="http://exslt.org/dates-and-times" extension-element-prefixes="date">

  
<xsl:template match="cpe:cpe-list">
  <xsl:copy>
    <xsl:for-each select="cpe:cpe-item[floor (date:seconds (meta:item-metadata/@modification-date)) &gt; number($refdate)]">
      <xsl:copy-of select="."/>
    </xsl:for-each>
  </xsl:copy>
</xsl:template>

</xsl:stylesheet>

