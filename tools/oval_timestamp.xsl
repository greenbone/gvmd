<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Select OVAL definitions which have been updated after
a certain date.

Authors:
Henri Doreau <henri.doreau@greenbone.net>
Timo Pollmeier <timo.pollmeier@greenbone.net>

Copyright:
Copyright (C) 2011 - 2012 Greenbone Networks GmbH

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
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.3"
  xmlns:meta="http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2"
  xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:config="http://scap.nist.gov/schema/configuration/0.1"
  xmlns:cpe="http://cpe.mitre.org/dictionary/2.0"
  xmlns:str="http://exslt.org/strings"
  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
  xmlns:oval_definitions="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xsi:schemaLocation="http://scap.nist.gov/schema/configuration/0.1 http://nvd.nist.gov/schema/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.3 http://nvd.nist.gov/schema/scap-core_0.3.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 http://nvd.nist.gov/schema/cpe-dictionary-metadata_0.2.xsd"
  extension-element-prefixes="str"
  >
  <xsl:output method="text"/>
  
  <xsl:template match="/">SELECT strftime('%s','<xsl:copy-of select="oval_definitions:oval_definitions/oval_definitions:generator/oval:timestamp"/>');</xsl:template>

</xsl:stylesheet>
