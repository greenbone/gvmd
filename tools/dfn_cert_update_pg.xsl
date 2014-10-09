<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id$
Description: Generate SQL (Postgres compatible) queries to update
the DFN-CERT tables of the CERT database.

Authors:
Timo Pollmeier <timo.pollmeier@greenbone.net>

Copyright:
Copyright (C) 2013, 2014 Greenbone Networks GmbH

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
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:dfncert="http://www.dfn-cert.de/dfncert.dtd"
  xmlns:atom="http://www.w3.org/2005/Atom"
  xmlns:str="http://exslt.org/strings"
  xmlns:date="http://exslt.org/dates-and-times"
  xmlns:func="http://exslt.org/functions"
  xmlns:openvas="http://openvas.org"
  extension-element-prefixes="str date func openvas">
  <xsl:output method="text"/>
  <xsl:param name="refdate" select="'0'"/>

  <func:function name="openvas:sql-quote">
    <xsl:param name="sql"/>
    <xsl:variable name="single">'</xsl:variable>
    <xsl:variable name="pair">''</xsl:variable>
    <func:result select="str:replace ($sql, $single, $pair)"/>
  </func:function>

  <xsl:template match="/">
SET search_path TO cert;
BEGIN TRANSACTION;

CREATE FUNCTION merge_dfn_cert_adv (uuid_arg TEXT,
                                    name_arg TEXT,
                                    comment_arg TEXT,
                                    creation_time_arg INTEGER,
                                    modification_time_arg INTEGER,
                                    title_arg TEXT,
                                    summary_arg TEXT,
                                    cve_refs_arg INTEGER)
RETURNS VOID AS $$
BEGIN
  LOOP
    UPDATE dfn_cert_advs
    SET name = name_arg,
        comment = comment_arg,
        creation_time = creation_time_arg,
        modification_time = modification_time_arg,
        title = title_arg,
        summary = summary_arg,
        cve_refs = cve_refs_arg
    WHERE uuid = uuid_arg;
    IF found THEN
      RETURN;
    END IF;
    BEGIN
      INSERT INTO dfn_cert_advs (uuid, name, comment, creation_time,
                                 modification_time, title, summary, cve_refs)
      VALUES (uuid_arg, name_arg, comment_arg, creation_time_arg,
              modification_time_arg, title_arg, summary_arg, cve_refs_arg);
      RETURN;
    EXCEPTION WHEN unique_violation THEN
      -- Try again.
    END;
  END LOOP;
END;
$$
LANGUAGE plpgsql;

CREATE FUNCTION merge_dfn_cert_cve (adv_id_arg INTEGER,
                                    cve_name_arg TEXT)
RETURNS VOID AS $$
BEGIN
<!--
  The SQLite3 version does INSERT OR REPLACE but there is no primary key, so
  just INSERT.

  LOOP
    UPDATE dfn_cert_cves
    SET adv_id = adv_id_arg,
        cve_name = cve_name_arg
    WHERE adv_id = adv_id_arg AND cve_name = cve_name_arg;
    IF found THEN
      RETURN;
    END IF;
    BEGIN
      INSERT INTO dfn_cert_cves (adv_id, cve_name)
      VALUES (adv_id_arg, cve_name_arg);
      RETURN;
    EXCEPTION WHEN unique_violation THEN
      /* Try again. */
    END;
  END LOOP;
-->
  INSERT INTO dfn_cert_cves (adv_id, cve_name)
  VALUES (adv_id_arg, cve_name_arg);
END;
$$
LANGUAGE plpgsql;

  <xsl:apply-templates select="atom:feed/atom:entry"/>

DROP FUNCTION merge_dfn_cert_adv (uuid_arg TEXT,
                                  name_arg TEXT,
                                  comment_arg TEXT,
                                  creation_time_arg INTEGER,
                                  modification_time_arg INTEGER,
                                  title_arg TEXT,
                                  summary_arg TEXT,
                                  cve_refs_arg INTEGER);

DROP FUNCTION merge_dfn_cert_cve (adv_id_arg INTEGER,
                                  cve_name_arg TEXT);

COMMIT;
  </xsl:template>

  <xsl:template match="atom:entry">
  <xsl:choose>
  <xsl:when test="floor (date:seconds (atom:updated)) &gt; number($refdate)">
  SELECT merge_dfn_cert_adv
   ('<xsl:value-of select="dfncert:refnum"/>',
    '<xsl:value-of select="dfncert:refnum"/>',
    '',
    <xsl:value-of select="floor (date:seconds (atom:published/text()))"/>,
    <xsl:value-of select="floor (date:seconds (atom:updated/text()))"/>,
    '<xsl:value-of select="openvas:sql-quote (atom:title/text())"/>',
    '<xsl:value-of select="openvas:sql-quote (atom:summary/text())"/>',
    <xsl:value-of select="count(dfncert:cve)"/>);

  <xsl:variable name="refnum" select="dfncert:refnum"/>
  <xsl:for-each select="dfncert:cve">
  <xsl:for-each select="str:tokenize (str:replace (text (), 'CVE ', 'CVE-'), ' ')">
  <xsl:if test="starts-with (text (), 'CVE-') and (string-length (text ()) &gt;= 13) and string (number(substring (text (), 4, 4))) != 'NaN'">
  SELECT merge_dfn_cert_cve
   ((SELECT id FROM dfn_cert_advs WHERE name = '<xsl:value-of select="$refnum"/>'),
    '<xsl:value-of select="."/>');
  </xsl:if>
  </xsl:for-each>
  </xsl:for-each>
  </xsl:when>
  <xsl:otherwise>
  /* filtered entry dated <xsl:value-of select="atom:updated/text()"/> */
  </xsl:otherwise>
  </xsl:choose>
  </xsl:template>
</xsl:stylesheet>
