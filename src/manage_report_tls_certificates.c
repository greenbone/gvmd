/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report tls certificates.
 *
 * Non-SQL report tls certificates code for the GVM management layer.
 */

#include "manage_report_tls_certificates.h"
#include "manage_filters.h"
#include "manage_settings.h"
#include "manage_sql_report_hosts.h"
#include "manage_sql_report_tls_certificates.h"

#include <gvm/util/fileutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/**
 * @brief Send report TLS certificates XML to the client.
 *
 * @param[in]  report                        Report.
 * @param[in]  get                           GET command data.
 * @param[in]  is_container_scanning_report  Whether this is a container scan report.
 * @param[in]  send                          Function to write to client.
 * @param[in]  send_data_1                   Second argument to @p send.
 * @param[in]  send_data_2                   Third argument to @p send.
 *
 * @return 0 on success, -1 on error, 2 if filter was not found.
 */
int
manage_send_report_tls_certificates (report_t report,
                                     const get_data_t *get,
                                     gboolean is_container_scanning_report,
                                     gboolean (*send) (const char *,
                                       int (*) (const char *,
                                                void *),
                                       void *),
                                     int (*send_data_1) (const char *, void *),
                                     void *send_data_2)
{
  gchar *xml_file;
  gchar *term;
  char xml_dir[] = "/tmp/gvmd_XXXXXX";
  gboolean xml_dir_created = FALSE;
  char chunk[MANAGE_SEND_REPORT_CHUNK_SIZE + 1];
  FILE *stream;
  int ret;
  int result_hosts_only;
  array_t *result_hosts;
  iterator_t results;
  int results_initialized;

  term = NULL;
  xml_file = NULL;
  stream = NULL;
  result_hosts = NULL;
  results_initialized = 0;
  result_hosts_only = 0;

  if (get == NULL)
    {
      g_warning ("%s: get is NULL", __func__);
      return -1;
    }

  /* Derive filter controls, including whether only hosts with results
   * should be included.
   */
  ret = manage_report_filter_controls_from_get (get,
                                                &term,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL,
                                                &result_hosts_only,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL);
  if (ret)
    goto cleanup;

  if (mkdtemp (xml_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed", __func__);
      ret = -1;
      goto cleanup;
    }

  xml_dir_created = TRUE;

  if (get->details && result_hosts_only)
    {
      ret = fill_filtered_result_hosts (&result_hosts,
                                        get,
                                        report,
                                        &results,
                                        is_container_scanning_report);
      if (ret)
        {
          ret = -1;
          goto cleanup;
        }

      results_initialized = 1;
    }

  xml_file = g_strdup_printf ("%s/report-tls-certificates.xml", xml_dir);
  stream = fopen (xml_file, "w");
  if (stream == NULL)
    {
      g_warning ("%s: %s", __func__, strerror (errno));
      ret = -1;
      goto cleanup;
    }

  ret = print_report_tls_certificates_xml_summary_or_details (
    report,
    stream,
    get->details,
    result_hosts_only,
    result_hosts);

  if (fclose (stream))
    {
      stream = NULL;
      ret = -1;
      goto cleanup;
    }
  stream = NULL;

  if (ret)
    {
      ret = -1;
      goto cleanup;
    }

  stream = fopen (xml_file, "r");
  if (stream == NULL)
    {
      g_warning ("%s: %s", __func__, strerror (errno));
      ret = -1;
      goto cleanup;
    }

  while (1)
    {
      int left;
      char *dest;

      left = MANAGE_SEND_REPORT_CHUNK_SIZE;
      dest = chunk;

      while (1)
        {
          ret = fread (dest, 1, left, stream);
          if (ferror (stream))
            {
              g_warning ("%s: error after fread", __func__);
              ret = -1;
              goto cleanup;
            }

          left -= ret;
          if (left == 0 || feof (stream))
            break;
          dest += ret;
        }

      if (left < MANAGE_SEND_REPORT_CHUNK_SIZE)
        {
          chunk[MANAGE_SEND_REPORT_CHUNK_SIZE - left] = '\0';
          if (send (chunk, send_data_1, send_data_2))
            {
              g_warning ("%s: send error", __func__);
              ret = -1;
              goto cleanup;
            }
        }

      if (feof (stream))
        break;
    }

  ret = 0;

cleanup:
  if (stream)
    fclose (stream);

  if (results_initialized)
    cleanup_iterator (&results);

  if (result_hosts)
    array_free (result_hosts);

  g_free (xml_file);
  g_free (term);

  if (xml_dir_created)
    gvm_file_remove_recurse (xml_dir);

  return ret;
}