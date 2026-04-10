/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report tls certificates.
 *
 * SQL handlers for report tls certificates XML.
 */

#include "manage_sql_report_tls_certificates.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Print the XML for a report host's TLS certificates to a file stream.
 * @param[in]  report_host  The report host to get certificates from.
 * @param[in]  host_ip      The IP address of the report host.
 * @param[in]  stream       File stream to write to.
 *
 * @return 0 on success, -1 error.
 */
static int
print_report_host_tls_certificates_xml (report_host_t report_host,
                                        const char *host_ip,
                                        FILE *stream)
{
  iterator_t tls_certs;
  time_t activation_time, expiration_time;
  gchar *md5_fingerprint, *sha256_fingerprint, *subject, *issuer, *serial;
  gnutls_x509_crt_fmt_t certificate_format;

  if (report_host == 0
      || strcmp (host_ip, "") == 0)
    return -1;

  init_iterator (&tls_certs,
                 "SELECT rhd.value, rhd.name, rhd.source_name"
                 " FROM report_host_details AS rhd"
                 " WHERE rhd.report_host = %llu"
                 "   AND (source_description = 'SSL/TLS Certificate'"
                 "        OR source_description = 'SSL Certificate')",
                 report_host);

  while (next (&tls_certs))
    {
      const char *certificate_prefixed, *certificate_b64;
      gsize certificate_size;
      unsigned char *certificate;
      const char *scanner_fpr_prefixed, *scanner_fpr;
      gchar *quoted_scanner_fpr;
      char *ssldetails;
      iterator_t ports;
      gboolean valid;
      time_t now;

      certificate_prefixed = iterator_string (&tls_certs, 0);
      certificate_b64 = g_strrstr (certificate_prefixed, ":") + 1;

      certificate = g_base64_decode (certificate_b64, &certificate_size);

      scanner_fpr_prefixed = iterator_string (&tls_certs, 1);
      scanner_fpr = g_strrstr (scanner_fpr_prefixed, ":") + 1;

      quoted_scanner_fpr = sql_quote (scanner_fpr);

      activation_time = -1;
      expiration_time = -1;
      md5_fingerprint = NULL;
      sha256_fingerprint = NULL;
      subject = NULL;
      issuer = NULL;
      serial = NULL;
      certificate_format = 0;

      get_certificate_info ((gchar *) certificate,
                            certificate_size,
                            TRUE,
                            &activation_time,
                            &expiration_time,
                            &md5_fingerprint,
                            &sha256_fingerprint,
                            &subject,
                            &issuer,
                            &serial,
                            &certificate_format);

      if (sha256_fingerprint == NULL)
        sha256_fingerprint = g_strdup (scanner_fpr);

      ssldetails
        = sql_string ("SELECT rhd.value"
                      " FROM report_host_details AS rhd"
                      " WHERE report_host = %llu"
                      "   AND name = 'SSLDetails:%s'"
                      " LIMIT 1;",
                      report_host,
                      quoted_scanner_fpr);

      if (ssldetails)
        parse_ssldetails (ssldetails,
                          &activation_time,
                          &expiration_time,
                          &issuer,
                          &serial);
      else
        g_warning ("%s: No SSLDetails found for fingerprint %s",
                 __func__,
                 scanner_fpr);

      free (ssldetails);

      now = time (NULL);

      if ((expiration_time >= now || expiration_time == -1)
          && (activation_time <= now || activation_time == -1))
        {
          valid = TRUE;
        }
      else
        {
          valid = FALSE;
        }
      char *hostname = sql_string ("SELECT value FROM report_host_details"
                                   " WHERE report_host = %llu"
                                   "   AND name = 'hostname'",
                                   report_host);

      PRINT (stream,
             "<tls_certificate>"
             "<name>%s</name>"
             "<certificate format=\"%s\">%s</certificate>"
             "<sha256_fingerprint>%s</sha256_fingerprint>"
             "<md5_fingerprint>%s</md5_fingerprint>"
             "<valid>%d</valid>"
             "<activation_time>%s</activation_time>"
             "<expiration_time>%s</expiration_time>"
             "<subject_dn>%s</subject_dn>"
             "<issuer_dn>%s</issuer_dn>"
             "<serial>%s</serial>"
             "<host><ip>%s</ip><hostname>%s</hostname></host>",
             scanner_fpr,
             tls_certificate_format_str (certificate_format),
             certificate_b64,
             sha256_fingerprint,
             md5_fingerprint,
             valid,
             certificate_iso_time (activation_time),
             certificate_iso_time (expiration_time),
             subject,
             issuer,
             serial,
             host_ip,
             hostname ? hostname : "");

      g_free (certificate);
      g_free (md5_fingerprint);
      g_free (sha256_fingerprint);
      g_free (subject);
      g_free (issuer);
      g_free (serial);

      free (hostname);

      init_iterator (&ports,
                     "SELECT value FROM report_host_details"
                     " WHERE report_host = %llu"
                     "   AND name = 'SSLInfo'"
                     "   AND value LIKE '%%:%%:%s'",
                     report_host,
                     quoted_scanner_fpr);

      PRINT (stream, "<ports>");

      while (next (&ports))
        {
          const char *value;
          gchar *port;

          value = iterator_string (&ports, 0);
          port = g_strndup (value, g_strrstr (value, ":") - value - 1);

          PRINT (stream, "<port>%s</port>", port);

          g_free (port);
        }

      PRINT (stream, "</ports>");

      PRINT (stream, "</tls_certificate>");

      g_free (quoted_scanner_fpr);
      cleanup_iterator (&ports);
    }
  cleanup_iterator (&tls_certs);

  return 0;
}

/**
 * @brief Print TLS certificates XML for a report.
 *
 * If @p result_hosts_only is set, only the hosts from @p result_hosts are used.
 * Otherwise, TLS certificates for all report hosts are printed.
 *
 * @param[in]  report              Report to print TLS certificates for.
 * @param[in]  result_hosts_only   Whether to restrict output to @p result_hosts.
 * @param[in]  result_hosts        Array of host strings when @p result_hosts_only
 *                                 is true. May be freed by this function.
 * @param[in]  out                 Output stream.
 *
 * @return 0 on success, -1 on error.
 */
int
print_report_tls_certificates_xml (report_t report,
                                   gboolean result_hosts_only,
                                   array_t *result_hosts,
                                   FILE *out)
{
  PRINT (out, "<tls_certificates>");

  if (result_hosts_only)
    {
      gchar *result_host;
      int index = 0;

      while ((result_host = g_ptr_array_index (result_hosts, index++)))
        {
          gboolean present;
          iterator_t hosts;

          init_report_host_iterator (&hosts, report, result_host, 0);
          present = next (&hosts);
          if (present)
            {
              report_host_t report_host;

              report_host = host_iterator_report_host (&hosts);

              if (print_report_host_tls_certificates_xml (report_host,
                result_host,
                out))
                {
                  cleanup_iterator (&hosts);
                  goto fail;
                }
            }
          cleanup_iterator (&hosts);
        }

      array_free (result_hosts);
    }
  else
    {
      const char *host;
      iterator_t hosts;

      init_report_host_iterator (&hosts, report, NULL, 0);

      while (next (&hosts))
        {
          report_host_t report_host;

          report_host = host_iterator_report_host (&hosts);
          host = host_iterator_host (&hosts);

          if (print_report_host_tls_certificates_xml (report_host, host, out))
            {
              cleanup_iterator (&hosts);
              goto fail;
            }
        }

      cleanup_iterator (&hosts);
    }

  PRINT (out, "</tls_certificates>");
  return 0;

fail:
  PRINT (out, "</tls_certificates>");
  return -1;
}

/**
 * @brief Print report TLS certificates XML, returning either full details
 *        or only the count.
 *
 * @param[in]  report              The report.
 * @param[in]  out                 File stream.
 * @param[in]  details             Boolean flag whether to include full details.
 * @param[in]  result_hosts_only   Whether to restrict output to @p result_hosts.
 * @param[in]  result_hosts        Array of host strings to use when
 *                                 @p result_hosts_only is true.
 *
 * @return 0 on success, -1 on error.
 */
int
print_report_tls_certificates_xml_summary_or_details (report_t report,
                                                      FILE *out,
                                                      int details,
                                                      gboolean result_hosts_only,
                                                      array_t *result_hosts)
{
  if (details == 0)
    {
      PRINT (out,
             "<tls_certificates>"
             "<count>%i</count>"
             "</tls_certificates>",
             report_ssl_cert_count (report));
      return 0;
    }

  return print_report_tls_certificates_xml (report,
                                            result_hosts_only,
                                            result_hosts,
                                            out);
}

/**
 * @brief Count a report's total number of found SSL Certificates.
 *
 * @param[in]  report  Report.
 *
 * @return SSL Certificates count.
 */
int
report_ssl_cert_count (report_t report)
{
  return sql_int ("SELECT count (DISTINCT id) FROM report_host_details"
                  " WHERE report_host IN"
                  "  (SELECT id from report_hosts WHERE report = %llu)"
                  "  AND name = 'SSLInfo';",
                  report);
}
