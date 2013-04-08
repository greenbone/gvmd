<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:iana="http://www.iana.org/assignments" version="1.0">

<xsl:template match="/">
 BEGIN TRANSACTION;
 INSERT OR REPLACE INTO main.meta (name, value) VALUES ('portnames_timestamp', '<xsl:value-of select="iana:registry/iana:updated"/>');
  <xsl:apply-templates select="iana:registry/iana:record"/>
 END TRANSACTION;
</xsl:template>

<xsl:template match="iana:record">
  <xsl:choose>
    <xsl:when test="(iana:number &gt;= 0 and iana:number &lt; 65536)
                    and (iana:protocol='udp' or iana:protocol='tcp')
                    and (string-length(iana:name) &gt; 0)">
 INSERT INTO port_names (number, protocol, name) VALUES (<xsl:value-of select="iana:number"/>, '<xsl:value-of select="iana:protocol"/>' , '<xsl:value-of select="iana:name"/>');
    </xsl:when>
  </xsl:choose>
</xsl:template>
</xsl:stylesheet>
