<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="html"
                doctype-system="http://www.w3.org/TR/html4/strict.dtd"
                doctype-public="-//W3C//DTD HTML 4.01//EN"
                encoding="UTF-8" />

    <xsl:template match="scan_start">
	  Scan start: <xsl:apply-templates />
    </xsl:template>

    <xsl:template match="scan_end">
	  Scan end: <xsl:apply-templates />
    </xsl:template>

    <xsl:template match="get_report_response">
	  <xsl:apply-templates />
    </xsl:template>

    <xsl:template match="result">
	  <tr>
		<td>
		  <xsl:apply-templates select="type"/><br/>
		  Host: <xsl:apply-templates select="host"/><br/>
		  Port: <xsl:apply-templates select="port"/><br/>
		  NVT OID: <xsl:apply-templates select="nvt"/><br/>
		  <xsl:apply-templates select="description"/>
        </td>
	  </tr>
    </xsl:template>

    <xsl:template match="report">
		<h1>OpenVAS Scan Report</h1>

		<p>
		  This report lists all results.
		</p>

		<p>
		  <xsl:apply-templates select="scan_start" />
		  <br/>
		  <xsl:apply-templates select="scan_end" />
		</p>

	    <p>Results: <xsl:value-of select="count(result)"/></p>

		<table>
		  <xsl:apply-templates select="result"/>
		</table>
    </xsl:template>

    <xsl:template match="/">
	  <html>
		<head>
		  <link rel="stylesheet" type="text/css" href="./style.css" />
		  <title>OpenVAS Scan Report</title>
  	    </head>
		<body>
		  <xsl:apply-templates />
		</body>
	  </html>
	</xsl:template>

</xsl:stylesheet>
