<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html"
			  doctype-system="http://www.w3.org/TR/html4/strict.dtd"
			  doctype-public="-//W3C//DTD HTML 4.01//EN"
			  encoding="UTF-8" />

  <!-- <xsl:key name="host_results" match="*/result" use="host" /> -->
  <!-- <xsl:key name="host_ports" match="*/result[port]" use="../host" /> -->

  <xsl:template match="scan_start">
	Scan started: <xsl:apply-templates />
  </xsl:template>

  <xsl:template match="scan_end">
	Scan ended: <xsl:apply-templates />
  </xsl:template>

  <xsl:template match="get_report_response">
	<xsl:apply-templates />
  </xsl:template>

  <xsl:template match="result" mode="list">
	<tr>
	  <td>
		<xsl:apply-templates select="type"/><br/>
		Host: <xsl:apply-templates select="host"/><br/>
		Port: <xsl:apply-templates select="port"/><br/>
		NVT OID: <xsl:apply-templates select="nvt"/><br/>
		<xsl:apply-templates select="description"/><br/><br/>
	  </td>
	</tr>
  </xsl:template>

  <xsl:template match="result" mode="table">
	<tr>
	  <td>
		<xsl:choose>
		  <xsl:when test="type[. = 'Security Hole']">Vulnerability</xsl:when>
		  <xsl:when test="type[. = 'Security Note']">Informational</xsl:when>
		  <xsl:when test="type[. = 'Security Warning']">Warning</xsl:when>
		</xsl:choose>
	  </td>
	</tr>
	<tr>
	  <td>
		<xsl:apply-templates select="description"/><br/>
		OpenVAS ID:
		<xsl:variable name="oid" select="nvt"/>
		<a href="http://www.openvas.org/?oid={$oid}">
		  <xsl:value-of select="$oid"/>
		</a>
	  </td>
	</tr>
  </xsl:template>

  <xsl:template match="result" mode="issue">

	<xsl:choose>
      <!-- FIX This choose is an attempt to print the h5 only on the first
           result of a certain port, however it fails, as preceding refers
           to the original xml tree (instead of the sorted version currently
	       in use by the apply-template). -->
	  <xsl:when test="port/text() = preceding::port/text()">
		<h5 id="port:{port}"><xsl:value-of select="port"/></h5>
		<table>
		<tr>
		  <td>
			<xsl:choose>
			  <xsl:when test="type[. = 'Security Hole']">Vulnerability</xsl:when>
			  <xsl:when test="type[. = 'Security Note']">Informational</xsl:when>
			  <xsl:when test="type[. = 'Security Warning']">Warning</xsl:when>
			</xsl:choose>
		  </td>
		</tr>
		<tr>
		  <td>
			<xsl:apply-templates select="description"/><br/>
			OpenVAS ID:
			<xsl:variable name="oid" select="nvt"/>
			<a href="http://www.openvas.org/?oid={$oid}">
			  <xsl:value-of select="$oid"/>
			</a>
		  </td>
		</tr>
        </table>
	  </xsl:when>
	  <xsl:otherwise>
		<h5 id="port:{port}"><xsl:value-of select="port"/></h5>
		<table>
		  <tr>
		    <xsl:choose>
		      <xsl:when test="type[. = 'Security Hole']">
			    <td id="vulnerability">Vulnerability</td>
			  </xsl:when>
		      <xsl:when test="type[. = 'Security Note']">
			    <td id="informational">Informational</td>
			  </xsl:when>
		      <xsl:when test="type[. = 'Security Warning']">
			    <td id="warning">Warning</td>
			  </xsl:when>
			</xsl:choose>
		  </tr>
		  <tr>
			<td>
			  <xsl:apply-templates select="description"/><br/>
			  OpenVAS ID:
			  <xsl:variable name="oid" select="nvt"/>
			  <a href="http://www.openvas.org/?oid={$oid}">
				<xsl:value-of select="$oid"/>
			  </a>
			</td>
		  </tr>
		</table>
	  </xsl:otherwise>
	</xsl:choose>

  </xsl:template>

  <xsl:template match="report">
	<h1>Summary</h1>

	<p>
	  This report lists results from a scan, sorted by host.
	</p>

	<p>
	  <xsl:apply-templates select="scan_start" />
	  <br/>
	  <xsl:apply-templates select="scan_end" />
	</p>

	<table>
	  <tr>
		<td>Host</td>
		<td>Possible Issues</td>
		<td>Holes</td>
		<td>Warnings</td>
		<td>Notes</td>
		<td>False Positives</td>
	  </tr>
	  <xsl:for-each select="host_start" >
		<xsl:variable name="current_host" select="host/text()" />
		<tr>
		  <td>
			<a href="#{$current_host}"><xsl:value-of select="$current_host"/></a>
		  </td>
		  <td></td>
		  <td><xsl:value-of select="count(../result[host/text() = $current_host][type/text() = 'Security Hole'])"/></td>
		  <td><xsl:value-of select="count(../result[host/text() = $current_host][type/text() = 'Security Warning'])"/></td>
		  <td><xsl:value-of select="count(../result[host/text() = $current_host][type/text() = 'Security Note'])"/></td>
		  <td></td>
		</tr>
	  </xsl:for-each>
	  <tr>
		<td>Total: <xsl:value-of select="count(host_start)"/></td>
		<td></td>
		<td><xsl:value-of select="count(result[type/text() = 'Security Hole'])"/></td>
		<td><xsl:value-of select="count(result[type/text() = 'Security Warning'])"/></td>
		<td><xsl:value-of select="count(result[type/text() = 'Security Note'])"/></td>
		<td></td>
	  </tr>
	</table>

	<h1>Results per Host</h1>

	<xsl:for-each select="host_start" >
	  <xsl:variable name="current_host" select="host/text()" />

	  <h2 id="{$current_host}"><xsl:value-of select="host/text()"/></h2>
	  <p>
		Scanning of this host started at: <xsl:value-of select="text()"/><br/>
		Number of results: <xsl:value-of select="count(../result[host/text()=$current_host])"/><br/>
      <!-- Number of results: <xsl:value-of select="count(key('host_results', $current_host))"/> -->
	  </p>

	  <table>
		<tr>
		  <td>Service (Port)</td>
		  <td>Issue regarding port</td>
		</tr>

		<xsl:for-each select="../result[not(port/text() = preceding::port/text())]">
		  <xsl:sort select="port"/>
		  <xsl:sort select="type"/>
		  <tr>
			<xsl:variable name="port" select="port"/>
			<td><a href="#port:{port}"><xsl:value-of select="$port"/></a></td>
			<td><xsl:value-of select="type"/>(s) found</td>
		  </tr>
		</xsl:for-each>

      <!-- <xsl:apply-templates select="key('host_results', $current_host)" mode="FIX"/> -->

	  </table>

	  <h3>Security Issues and Fixes -- Host <xsl:value-of select="$current_host" /></h3>

	  <xsl:apply-templates select="../result[host/text()=$current_host]" mode="issue">
		<xsl:sort select="port"/>
		<xsl:sort select="type"/>
	  </xsl:apply-templates>

	</xsl:for-each>

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
