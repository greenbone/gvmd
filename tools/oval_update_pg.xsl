<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Generate SQL (Postgres compatible) queries to update
the OVAL database.

Authors:
Henri Doreau <henri.doreau@greenbone.net>
Timo Pollmeier <timo.pollmeier@greenbone.net>

Copyright:
Copyright (C) 2011 - 2014 Greenbone Networks GmbH

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
  xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:date="http://exslt.org/dates-and-times"
  xmlns:str="http://exslt.org/strings"
  xmlns:func="http://exslt.org/functions"
  xmlns:openvas="http://openvas.org"
  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
  xmlns:oval_definitions="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:oval_variables="http://oval.mitre.org/XMLSchema/oval-variables-5"
  xsi:schemaLocation="http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-common-schema.xsd http://oval.mitre.org/language/version5.10.1/ovaldefinition/complete/oval-definitions-schema.xsd"
  extension-element-prefixes="date str func openvas">
  <xsl:param name="refdate" select="0" />

  <xsl:output method="text"/>

  <xsl:variable name="filetimestamp"
    select="normalize-space(oval_definitions:oval_definitions/oval_definitions:generator/oval:timestamp)"/>

  <func:function name="openvas:sql-quote">
    <xsl:param name="sql"/>
    <xsl:variable name="single">'</xsl:variable>
    <xsl:variable name="pair">''</xsl:variable>
    <func:result select="str:replace ($sql, $single, $pair)"/>
  </func:function>

  <xsl:template match="oval_definitions:definition">
    <xsl:variable name="definitiondate" select="normalize-space((oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates/oval_definitions:submitted/@date | oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates/oval_definitions:status_change/@date | oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:dates/oval_definitions:modified/@date)[last()])" />

    <xsl:choose>
    <xsl:when test="$definitiondate='' or floor (date:seconds ($definitiondate)) &gt; number($refdate)">
    SELECT merge_ovaldef
     ('<xsl:value-of select="@id"/>_'||(SELECT id FROM ovalfiles WHERE xml_file = '<xsl:value-of select="$filename"/>'),
      '<xsl:value-of select="@id"/>',
      '',
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
      '<xsl:value-of select="@class"/>',
      '<xsl:value-of select="openvas:sql-quote (oval_definitions:metadata/oval_definitions:title/text())"/>',
      '<xsl:value-of select="openvas:sql-quote (oval_definitions:metadata/oval_definitions:description/text())"/>',
      '<xsl:copy-of select="$filename"/>',
      <xsl:choose>
        <xsl:when test="oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:status != ''">
          '<xsl:value-of  select="oval_definitions:metadata/oval_definitions:oval_repository/oval_definitions:status"/>'
        </xsl:when>
        <xsl:otherwise>
          <xsl:choose>
            <xsl:when test="translate(@deprecated, $smallcase, $uppercase) = 'TRUE'">
              <xsl:text>'DEPRECATED'</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:text>''</xsl:text>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:otherwise>
      </xsl:choose>,
      0.0,
      <xsl:value-of select="count(oval_definitions:metadata/oval_definitions:reference[translate(@source, $uppercase, $smallcase) = 'cve'])"/>);
      <xsl:for-each select="oval_definitions:metadata/oval_definitions:reference[translate(@source, $uppercase, $smallcase) = 'cve']">
      INSERT INTO affected_ovaldefs (cve, ovaldef)
        SELECT cves.id, ovaldefs.id
        FROM cves, ovaldefs
        WHERE cves.name='<xsl:value-of select="@ref_id"/>'
        AND ovaldefs.name = '<xsl:value-of select="../../@id"/>'
        AND NOT EXISTS (SELECT * FROM affected_ovaldefs
                        WHERE cve = cves.id AND ovaldef = ovaldefs.id);
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
SET search_path TO scap;
BEGIN TRANSACTION;

CREATE FUNCTION merge_ovaldef (uuid_arg TEXT,
                               name_arg TEXT,
                               comment_arg TEXT,
                               creation_time_arg INTEGER,
                               modification_time_arg INTEGER,
                               version_arg INTEGER,
                               deprecated_arg INTEGER,
                               def_class_arg TEXT,
                               title_arg TEXT,
                               description_arg TEXT,
                               xml_file_arg TEXT,
                               status_arg TEXT,
                               max_cvss_arg FLOAT,
                               cve_refs_arg INTEGER)
RETURNS VOID AS $$
BEGIN
  LOOP
    UPDATE ovaldefs
    SET name = name_arg,
        comment = comment_arg,
        creation_time = creation_time_arg,
        modification_time = modification_time_arg,
        version = version_arg,
        deprecated = deprecated_arg,
        def_class = def_class_arg,
        title = title_arg,
        description = description_arg,
        xml_file = xml_file_arg,
        status = status_arg,
        max_cvss = max_cvss_arg,
        cve_refs = cve_refs_arg
    WHERE uuid = uuid_arg;
    IF found THEN
      RETURN;
    END IF;
    BEGIN
      INSERT INTO ovaldefs (uuid, name, comment, creation_time,
                            modification_time, version, deprecated, def_class,
                            title, description, xml_file, status, max_cvss,
                            cve_refs)
      VALUES (uuid_arg, name_arg, comment_arg, creation_time_arg,
              modification_time_arg, version_arg, deprecated_arg, def_class_arg,
              title_arg, description_arg, xml_file_arg, status_arg,
              max_cvss_arg, cve_refs_arg);
      RETURN;
    EXCEPTION WHEN unique_violation THEN
      -- Try again.
    END;
  END LOOP;
END;
$$
LANGUAGE plpgsql;

INSERT INTO ovalfiles (xml_file)
SELECT '<xsl:value-of select="$filename"/>'
WHERE NOT EXISTS (SELECT * FROM ovalfiles
                  WHERE xml_file = '<xsl:value-of select="$filename"/>');

    <xsl:apply-templates />

DROP FUNCTION merge_ovaldef (uuid_arg TEXT,
                             name_arg TEXT,
                             comment_arg TEXT,
                             creation_time_arg INTEGER,
                             modification_time_arg INTEGER,
                             version_arg INTEGER,
                             deprecated_arg INTEGER,
                             def_class_arg TEXT,
                             title_arg TEXT,
                             description_arg TEXT,
                             xml_file_arg TEXT,
                             status_arg TEXT,
                             max_cvss_arg FLOAT,
                             cve_refs_arg INTEGER);

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
