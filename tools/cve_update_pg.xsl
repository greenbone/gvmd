<?xml version="1.0" encoding="UTF-8"?>
<!--
OpenVAS
$Id: cve_update.xsl 20229 2014-09-01 13:13:29Z mwiegand $
Description: Generate SQL (Postgres compatible) queries to update the CVE
database.

Authors:
Henri Doreau <henri.doreau@greenbone.net>
Timo Pollmeier <timo.pollmeier@greenbone.net>

Copyright:
Copyright (C) 2011, 2013, 2014 Greenbone Networks GmbH

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
  xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4"
  xmlns:cpe-lang="http://cpe.mitre.org/language/2.0"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:cve="http://scap.nist.gov/schema/feed/vulnerability/2.0"
  xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:str="http://exslt.org/strings"
  xmlns:patch="http://scap.nist.gov/schema/patch/0.1"
  extension-element-prefixes="str"
  >
<xsl:output method="text"/>

<xsl:template match="cve:entry">
  SELECT merge_cve ('<xsl:value-of select="@id"/>',
  '<xsl:value-of select="@id"/>',
  extract (epoch from '<xsl:value-of select="vuln:published-datetime"/>'::timestamptz)::integer,
  extract (epoch from '<xsl:value-of select="vuln:last-modified-datetime"/>'::timestamptz)::integer,
  <xsl:choose>
    <xsl:when test="string-length (vuln:cvss/cvss:base_metrics/cvss:score)">
      <xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:score"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:text>NULL</xsl:text>
    </xsl:otherwise>
  </xsl:choose>,
  '<xsl:value-of select='str:replace(vuln:summary/text(), "&#39;", "&#39;&#39;")'/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:access-vector"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:access-complexity"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:authentication"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:confidentiality-impact"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:integrity-impact"/>',
  '<xsl:value-of select="vuln:cvss/cvss:base_metrics/cvss:availability-impact"/>',
  '<xsl:for-each select="vuln:vulnerable-software-list/vuln:product">
     <xsl:value-of select='str:replace(str:replace(
       str:decode-uri(text()), "%7E", "~"),
       "&#39;", "&#39;&#39;")'/>
     <xsl:text> </xsl:text>
   </xsl:for-each>');

  <xsl:for-each select="vuln:vulnerable-software-list/vuln:product">
    <xsl:variable name="decoded_cpe" select='
      str:replace(
      str:replace(
      str:decode-uri(text()), "%7E", "~"),
      "&#39;", "&#39;&#39;")'/>
  SELECT merge_cpe ('<xsl:value-of select="$decoded_cpe"/>', '<xsl:value-of select="$decoded_cpe"/>');

  SELECT merge_affected_product ((SELECT id FROM cves WHERE uuid='<xsl:value-of select="../../@id"/>'),
  (SELECT id FROM cpes WHERE name='<xsl:value-of select="$decoded_cpe"/>'));
  </xsl:for-each>
</xsl:template>

<xsl:template match="/">
<!-- Activate delete triggers for replace -->
<!-- FIX PRAGMA recursive_triggers='ON'; -->
SET search_path TO scap;
BEGIN TRANSACTION;

CREATE FUNCTION merge_cve (uuid_arg TEXT,
                           name_arg TEXT,
                           creation_time_arg INTEGER,
                           modification_time_arg INTEGER,
                           cvss_arg FLOAT,
                           description_arg TEXT,
                           vector_arg TEXT,
                           complexity_arg TEXT,
                           authentication_arg TEXT,
                           confidentiality_impact_arg TEXT,
                           integrity_impact_arg TEXT,
                           availability_impact_arg TEXT,
                           products_arg TEXT)
RETURNS VOID AS $$
BEGIN
  LOOP
    UPDATE cves
    SET name = name_arg,
        creation_time = creation_time_arg,
        modification_time = modification_time_arg,
        cvss = cvss_arg,
        description = description_arg,
        vector = vector_arg,
        complexity = complexity_arg,
        authentication = authentication_arg,
        confidentiality_impact = confidentiality_impact_arg,
        integrity_impact = integrity_impact_arg,
        availability_impact = availability_impact_arg,
        products = products_arg
    WHERE uuid = uuid_arg;
    IF found THEN
      RETURN;
    END IF;
    BEGIN
      INSERT INTO cves (uuid, name, creation_time, modification_time, cvss,
                        description, vector, complexity, authentication,
                        confidentiality_impact, integrity_impact,
                        availability_impact, products)
      VALUES (uuid_arg, name_arg, creation_time_arg, modification_time_arg,
              cvss_arg, description_arg, vector_arg, complexity_arg,
              authentication_arg, confidentiality_impact_arg,
              integrity_impact_arg, availability_impact_arg, products_arg);
      RETURN;
    EXCEPTION WHEN unique_violation THEN
      -- Try again.
    END;
  END LOOP;
END;
$$
LANGUAGE plpgsql;

CREATE FUNCTION merge_cpe (uuid_arg TEXT,
                           name_arg TEXT)
RETURNS VOID AS $$
BEGIN
  LOOP
    UPDATE cpes SET name = name_arg WHERE uuid = uuid_arg;
    IF found THEN
      RETURN;
    END IF;
    BEGIN
      INSERT INTO cpes (uuid, name) VALUES (uuid_arg, name_arg);
      RETURN;
    EXCEPTION WHEN unique_violation THEN
      -- Try again.
    END;
  END LOOP;
END;
$$
LANGUAGE plpgsql;

CREATE FUNCTION merge_affected_product (cve_arg INTEGER,
                                        cpe_arg INTEGER)
RETURNS VOID AS $$
BEGIN
  LOOP
    UPDATE affected_products
    SET cve = cve_arg, cpe = cpe_arg
    WHERE cve = cve_arg AND cpe = cpe_arg;
    IF found THEN
      RETURN;
    END IF;
    BEGIN
      INSERT INTO affected_products (cve, cpe) VALUES (cve_arg, cpe_arg);
      RETURN;
    EXCEPTION WHEN unique_violation THEN
      -- Try again.
    END;
  END LOOP;
END;
$$
LANGUAGE plpgsql;

  <xsl:apply-templates/>

DROP FUNCTION merge_cve (uuid_arg TEXT,
                         name_arg TEXT,
                         creation_time_arg INTEGER,
                         modification_time_arg INTEGER,
                         cvss_arg FLOAT,
                         description_arg TEXT,
                         vector_arg TEXT,
                         complexity_arg TEXT,
                         authentication_arg TEXT,
                         confidentiality_impact_arg TEXT,
                         integrity_impact_arg TEXT,
                         availability_impact_arg TEXT,
                         products_arg TEXT);

DROP FUNCTION merge_affected_product (cve_arg INTEGER,
                                      cpe_arg INTEGER);

DROP FUNCTION merge_cpe (uuid_arg TEXT,
                         name_arg TEXT);

COMMIT;
</xsl:template>

</xsl:stylesheet>
