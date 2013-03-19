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
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:str="http://exslt.org/strings"
  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
  xmlns:oval_definitions="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:oval_variables="http://oval.mitre.org/XMLSchema/oval-variables-5"
  xmlns:oval_system_char="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"
  xmlns:oval_results="http://oval.mitre.org/XMLSchema/oval-results-5"
  xsi:schemaLocation="http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-common-schema.xsd http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-definitions-schema.xsd"
  extension-element-prefixes="str"
  >
  <xsl:output method="text"/>
  
  <xsl:template match="/"><xsl:value-of select="normalize-space(oval_definitions:oval_definitions/oval_definitions:generator/oval:timestamp|oval_variables:oval_variables/oval_variables:generator/oval:timestamp|oval_system_char:oval_system_characteristics/oval_system_char:generator/oval:timestamp|oval_results:oval_results/oval_results:generator/oval:timestamp)"/>
  </xsl:template>

</xsl:stylesheet>
