<?xml version="1.0" encoding="UTF-8"?>
<!--
Copyright (C) 2011-2018 Greenbone Networks GmbH

SPDX-License-Identifier: AGPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->

<!-- Select a CVE item by name. -->

<xsl:stylesheet version="1.0" 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:str="http://exslt.org/strings"
  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
  xmlns:oval_definitions="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xsi:schemaLocation="http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-common-schema.xsd http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-definitions-schema.xsd"
  extension-element-prefixes="str"
  >

<xsl:output method="html"/>

<xsl:template match="/">
  <xsl:copy-of select="//oval_definitions:definition[@id = $refname]"/>
</xsl:template>

</xsl:stylesheet>

