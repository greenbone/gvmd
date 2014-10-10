<!--
OpenVAS
$Id$
Description: Generate SQL queries to update port names.

Authors:
Hani Benhabiles <hani.benhabiles@greenbone.net>

Copyright:
Copyright (C) 2013 Greenbone Networks GmbH

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

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:iana="http://www.iana.org/assignments" version="1.0">

<xsl:template match="/">
  BEGIN TRANSACTION;
  DELETE FROM meta WHERE name = 'portnames_timestamp';
  INSERT INTO meta (name, value)
  VALUES ('portnames_timestamp', '<xsl:value-of select="iana:registry/iana:updated"/>');
  <xsl:apply-templates select="iana:registry/iana:record"/>
  END TRANSACTION;
</xsl:template>

<xsl:template match="iana:record">
  <xsl:choose>
    <xsl:when test="(iana:number &gt;= 0 and iana:number &lt; 65536)
                    and (iana:protocol='udp' or iana:protocol='tcp')
                    and (string-length(iana:name) &gt; 0)">
      DELETE FROM port_names
      WHERE number = <xsl:value-of select="iana:number"/>
      AND protocol = '<xsl:value-of select="iana:protocol"/>';
      INSERT INTO port_names (number, protocol, name)
      VALUES (<xsl:value-of select="iana:number"/>,
              '<xsl:value-of select="iana:protocol"/>',
              '<xsl:value-of select="iana:name"/>');
    </xsl:when>
  </xsl:choose>
</xsl:template>
</xsl:stylesheet>
