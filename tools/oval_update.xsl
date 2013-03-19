<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Generate SQL (SQLite compatible) queries to update
the OVAL database.

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
  xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:str="http://exslt.org/strings"
  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
  xmlns:oval_definitions="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:oval_variables="http://oval.mitre.org/XMLSchema/oval-variables-5"
  xsi:schemaLocation="http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-common-schema.xsd http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-definitions-schema.xsd"
  extension-element-prefixes="str"
  >
  <xsl:param name="refdate" select="0" />

  <xsl:output method="text"/>

  <xsl:variable name="filetimestamp"
    select="normalize-space(oval_definitions:oval_definitions/oval_definitions:generator/oval:timestamp)"/>

  <xsl:template match="oval_definitions:definition">
    <xsl:variable name="definitiondate" select="normalize-space((oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates/oval_definitions:submitted/@date | oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates/oval_definitions:status_change/@date | oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates/oval_definitions:modified/@date)[last()])" />

    <xsl:choose>
    <xsl:when test="$definitiondate='' or number(translate(substring($definitiondate,1,10),'-','')) &gt; number($refdate)">
    INSERT OR REPLACE INTO ovaldefs (
      uuid,
      name,
      comment,
      creation_time,
      modification_time,
      version,
      deprecated,
      def_class,
      title,
      description,
      xml_file,
      status
    ) VALUES (
      "<xsl:value-of select="@id"/>",
      "<xsl:value-of select="@id"/>",
      "",
      <xsl:choose>
      <xsl:when test="$definitiondate != ''"><xsl:apply-templates select="oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates"/>
      </xsl:when>
      <xsl:otherwise>strftime('%s', '<xsl:copy-of select="$filetimestamp"/>'),
      strftime('%s', '<xsl:copy-of select="$filetimestamp"/>'),
      </xsl:otherwise>
      </xsl:choose>
      <xsl:value-of select="@version"/>,
      <xsl:call-template name="boolean_def_false">
        <xsl:with-param name="value" select="@deprecated"/>
      </xsl:call-template>,
      "<xsl:value-of select="@class"/>",
      "<xsl:value-of select="str:replace(oval_definitions:metadata/oval_definitions:title/text(), '&quot;', '&quot;&quot;')"/>",
      "<xsl:value-of select="str:replace(oval_definitions:metadata/oval_definitions:description/text(), '&quot;', '&quot;&quot;')"/>",
      "<xsl:copy-of select="$filename"/>",
      <xsl:choose>
        <xsl:when test="oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:status != ''">
          "<xsl:value-of  select="oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:status"/>"
        </xsl:when>
        <xsl:otherwise>
          <xsl:choose>
            <xsl:when test="translate(@deprecated, $smallcase, $uppercase) = 'TRUE'">
              <xsl:text>"DEPRECATED"</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:text>""</xsl:text>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:otherwise>
      </xsl:choose>
    );
    </xsl:when>
    <xsl:otherwise>
    /* Filtered <xsl:value-of select="@id"/> (<xsl:value-of select="$definitiondate"/>) */
    </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="oval_definitions:dates"><xsl:choose>
      <xsl:when test="oval_definitions:submitted/@date | oval_definitions:status_change/@date | oval_definitions:modified/@date != ''">strftime('%s', '<xsl:value-of select="(oval_definitions:submitted/@date | oval_definitions:status_change/@date | oval_definitions:modified/@date) [1]"/>'),
      strftime('%s', '<xsl:value-of select="(oval_definitions:submitted/@date | oval_definitions:status_change/@date | oval_definitions:modified/@date) [last()]"/>'),
      </xsl:when>
      <xsl:otherwise>strftime('%s', '<xsl:copy-of select="$timestamp"/>'),
      strftime('%s', '<xsl:copy-of select="$timestamp"/>'),
      </xsl:otherwise>
  </xsl:choose>
  </xsl:template>

  <xsl:template match="oval_definitions:generator" />
  <xsl:template match="oval_definitions:tests" />
  <xsl:template match="oval_definitions:objects" />
  <xsl:template match="oval_definitions:states" />
  <xsl:template match="oval_definitions:variables" />

  <xsl:template match="oval_variables:variable" />
  <xsl:template match="oval_variables:generator" />

  <xsl:template match="/">
    BEGIN TRANSACTION;
    <xsl:apply-templates />
    COMMIT;
  </xsl:template>

  <xsl:variable name="smallcase" select="'abcdefghijklmnopqrstuvwxyz'" />
  <xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

  <xsl:template name="boolean_def_false">
    <xsl:param name="value"/>
    <xsl:choose>
      <xsl:when test="translate($value, $smallcase, $uppercase) = 'TRUE'">
        <xsl:text>1</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>0</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>
</xsl:stylesheet>
