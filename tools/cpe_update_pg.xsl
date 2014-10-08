<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id: cpe_update.xsl 20229 2014-09-01 13:13:29Z mwiegand $
Description: Generate SQL (Postgres compatible) queries to update the CPE database.

Authors:
Henri Doreau <henri.doreau@greenbone.net>

Copyright:
Copyright (C) 2011, 2014 Greenbone Networks GmbH

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
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.3"
  xmlns:meta="http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2"
  xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:config="http://scap.nist.gov/schema/configuration/0.1"
  xmlns:cpe="http://cpe.mitre.org/dictionary/2.0"
  xmlns:str="http://exslt.org/strings"
  xsi:schemaLocation="http://scap.nist.gov/schema/configuration/0.1 http://nvd.nist.gov/schema/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.3 http://nvd.nist.gov/schema/scap-core_0.3.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 http://nvd.nist.gov/schema/cpe-dictionary-metadata_0.2.xsd"
  extension-element-prefixes="str"
  >
  <xsl:output method="text"/>

  <xsl:template match="cpe:cpe-item">
    <xsl:variable name="decoded_name"
                  select='str:replace(
                          str:replace(
                          str:decode-uri(@name),
                          "%7E", "~"),
                          "&#39;", "&#39;&#39;")'/>
    SELECT merge_cpe ('<xsl:value-of select="$decoded_name"/>',
    '<xsl:value-of select="$decoded_name"/>',
    '<xsl:value-of select='str:replace(cpe:title[@xml:lang = "en-US"], "&#39;", "&#39;&#39;")'/>',
    extract (epoch from '<xsl:value-of select="meta:item-metadata/@modification-date"/>'::timestamptz)::integer,
    extract (epoch from '<xsl:value-of select="meta:item-metadata/@modification-date"/>'::timestamptz)::integer,
    '<xsl:value-of select="meta:item-metadata/@status"/>',
    <xsl:call-template name="value_or_null">
      <xsl:with-param name="value" select="meta:item-metadata/@deprecated-by-nvd-id"/>
    </xsl:call-template>,
    '<xsl:value-of select="meta:item-metadata/@nvd-id"/>'
    );
  </xsl:template>

  <xsl:template match="cpe:generator"/>

  <xsl:template match="/">
    SET search_path TO scap;
    BEGIN TRANSACTION;
    CREATE FUNCTION merge_cpe (uuid_arg TEXT, name_arg TEXT, title_arg TEXT,
                               creation_time_arg INTEGER,
                               modification_time_arg INTEGER, status_arg TEXT,
                               deprecated_by_id_arg INTEGER, nvd_id_arg TEXT)
    RETURNS VOID AS $$
    BEGIN
      LOOP
        UPDATE cpes
        SET name = name_arg, title = title_arg,
            creation_time = creation_time_arg,
            modification_time = modification_time_arg,
            status = status_arg,
            deprecated_by_id = deprecated_by_id_arg,
            nvd_id = nvd_id_arg
        WHERE uuid = uuid_arg;
        IF found THEN
          RETURN;
        END IF;
        BEGIN
          INSERT INTO cpes (uuid, name, title, creation_time, modification_time,
                            status, deprecated_by_id, nvd_id)
          VALUES (uuid_arg, name_arg, title_arg, creation_time_arg,
                  modification_time_arg, status_arg, deprecated_by_id_arg,
                  nvd_id_arg);
          RETURN;
        EXCEPTION WHEN unique_violation THEN
          -- Try again.
        END;
      END LOOP;
    END;
    $$
    LANGUAGE plpgsql;
    <xsl:apply-templates/>
    DROP FUNCTION merge_cpe (uuid_arg TEXT, name_arg TEXT, title_arg TEXT,
                             creation_time_arg INTEGER,
                             modification_time_arg INTEGER, status_arg TEXT,
                             deprecated_by_id_arg INTEGER, nvd_id_arg TEXT);
    COMMIT;
  </xsl:template>

  <xsl:template name="value_or_null">
    <xsl:param name="value"/>
    <xsl:choose>
      <xsl:when test="$value">
        <xsl:value-of select="$value"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>NULL</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>
</xsl:stylesheet>

