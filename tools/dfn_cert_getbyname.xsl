<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id: cve_getbyname.xsl 11660 2011-09-22 14:22:40Z hdoreau $
Description: Select a CVE item by name.

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
<xsl:stylesheet version="1.0" 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:str="http://exslt.org/strings"
  xmlns:dfncert="https://www.dfn-cert.de/dfncert.dtd"
  xmlns:atom="http://www.w3.org/2005/Atom"
  extension-element-prefixes="str"
  >

<xsl:output method="html"/>

<xsl:template match="/">
  <xsl:copy-of select="//atom:entry[substring-before(substring-after(atom:id/text(),'https://portal.cert.dfn.de/adv/'),'/') = $refname]"/>
</xsl:template>

</xsl:stylesheet>

