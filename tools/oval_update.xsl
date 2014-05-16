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
  xmlns:date="http://exslt.org/dates-and-times"
  xmlns:str="http://exslt.org/strings"
  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
  xmlns:oval_definitions="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:oval_variables="http://oval.mitre.org/XMLSchema/oval-variables-5"
  xsi:schemaLocation="http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-common-schema.xsd http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-definitions-schema.xsd"
  extension-element-prefixes="date str"
  >
  <xsl:param name="refdate" select="0" />

  <xsl:output method="text"/>

  <xsl:variable name="filetimestamp"
    select="normalize-space(oval_definitions:oval_definitions/oval_definitions:generator/oval:timestamp)"/>

  <xsl:template match="oval_definitions:definition">
    <xsl:variable name="definitiondate" select="normalize-space((oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates/oval_definitions:submitted/@date | oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates/oval_definitions:status_change/@date | oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates/oval_definitions:modified/@date)[last()])" />

    <xsl:choose>
    <xsl:when test="$definitiondate='' or floor (date:seconds ($definitiondate)) &gt; number($refdate)">
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
      status,
      max_cvss,
      cve_refs
    ) VALUES (
      "<xsl:value-of select="@id"/>_"||(SELECT id FROM ovalfiles WHERE xml_file = "<xsl:value-of select="$filename"/>"),
      "<xsl:value-of select="@id"/>",
      "",
      <xsl:choose>
      <xsl:when test="$definitiondate != ''"><xsl:apply-templates select="oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates"/>
      </xsl:when>
      <xsl:otherwise><xsl:value-of select="floor (date:seconds ($filetimestamp))"/>,
      <xsl:value-of select="floor (date:seconds ($filetimestamp))"/>,
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
      </xsl:choose>,
      0.0,
      <xsl:value-of select="count(oval_definitions:metadata/oval_definitions:reference[translate(@source, $uppercase, $smallcase) = 'cve'])"/>
    );
      <xsl:for-each select="oval_definitions:metadata/oval_definitions:reference[translate(@source, $uppercase, $smallcase) = 'cve']">
      INSERT OR IGNORE INTO affected_ovaldefs (cve, ovaldef)
        SELECT cves.id, ovaldefs.id
        FROM cves, ovaldefs
        WHERE cves.name='<xsl:value-of select="@ref_id"/>'
          AND ovaldefs.name = '<xsl:value-of select="../../@id"/>';
      </xsl:for-each>
    </xsl:when>
    <xsl:otherwise>
    /* Filtered <xsl:value-of select="@id"/> (<xsl:value-of select="$definitiondate"/>) */
    </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="oval_definitions:dates"><xsl:choose>
      <xsl:when test="oval_definitions:submitted/@date | oval_definitions:status_change/@date | oval_definitions:modified/@date != ''"><xsl:value-of select="floor (date:seconds ((oval_definitions:submitted/@date | oval_definitions:status_change/@date | oval_definitions:modified/@date) [1]))"/>,
      <xsl:value-of select="floor (date:seconds ((oval_definitions:submitted/@date | oval_definitions:status_change/@date | oval_definitions:modified/@date) [last()]))"/>,
      </xsl:when>
      <xsl:otherwise><xsl:copy-of select="floor (date:seconds ($timestamp))"/>,
      <xsl:copy-of select="floor (date:seconds ($timestamp))"/>,
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

    INSERT OR IGNORE INTO ovalfiles (xml_file)
      VALUES ("<xsl:value-of select="$filename"/>");

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
