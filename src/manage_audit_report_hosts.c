/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Audit report hosts.
 *
 * Non-SQL audit report hosts code for the GVM management layer.
 */

#include "manage_audit_report_hosts.h"

#include "manage_filters.h"
#include "manage_report_common.h"
#include "manage_sql_audit_report_hosts.h"
#include "manage_sql_report_hosts.h"

#include <gvm/util/fileutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Send audit report hosts XML to the client.
 *
 * @param[in]  report       Audit report.
 * @param[in]  get          GET command data.
 * @param[in]  lean         Whether to send lean host data.
 * @param[in]  send         Function to write to client.
 * @param[in]  send_data_1  Second argument to @p send.
 * @param[in]  send_data_2  Third argument to @p send.
 *
 * @return 0 on success, -1 on error, 2 if the filter was not found,
 *         or 3 if the report usage type is not audit.
 */
int
manage_send_audit_report_hosts (
  report_t report,
  const get_data_t *get,
  int lean,
  gboolean (*send) (const char *,
                    int (*) (const char *, void *),
                    void *),
  int (*send_data_1) (const char *, void *),
  void *send_data_2)
{
  print_report_context_t ctx;
  get_data_t get_ignore_pagination;
  gchar *xml_file;
  gchar *term;
  gchar *host_filter;
  char xml_dir[] = "/tmp/gvmd_XXXXXX";
  gboolean xml_dir_created;
  char chunk[MANAGE_SEND_REPORT_CHUNK_SIZE + 1];
  FILE *stream;
  int ret;
  int result_hosts_only;
  array_t *result_hosts;
  iterator_t results;
  int results_initialized;

  memset (&ctx, 0, sizeof (ctx));

  xml_file = NULL;
  term = NULL;
  host_filter = NULL;
  stream = NULL;
  result_hosts = NULL;
  xml_dir_created = FALSE;
  results_initialized = 0;
  result_hosts_only = 0;

  if (report == 0 || get == NULL || send == NULL)
    {
      g_warning ("%s: Invalid argument", __func__);
      return -1;
    }

  ret = validate_get_report_usage_type (report,
                                        REPORT_USAGE_TYPE_AUDIT);
  if (ret < 0)
    {
      g_warning ("%s: Failed to validate report usage type", __func__);
      return -1;
    }

  if (ret > 0)
    return 3;

  ctx.get = get;
  ctx.report = report;
  ctx.tsk_usage_type = g_strdup ("audit");

  get_ignore_pagination = *get;
  get_ignore_pagination.ignore_pagination = 1;
  get_ignore_pagination.ignore_max_rows_per_page = 1;

  /*
   * Resolve the report filters, including result_hosts_only and the
   * optional exact host filter.
   */
  ret = manage_report_filter_controls_from_get (
    &get_ignore_pagination,
    &term,
    NULL,
    NULL,
    NULL,
    NULL,
    &result_hosts_only,
    &host_filter,
    NULL,
    NULL,
    NULL,
    &ctx.compliance_levels,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL);

  if (ret)
    goto cleanup;

  print_report_init_f_hosts (&ctx);

  ctx.f_host_ports = g_hash_table_new_full (g_str_hash,
                                            g_str_equal,
                                            g_free,
                                            NULL);

  if (mkdtemp (xml_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed: %s",
                 __func__,
                 strerror (errno));
      ret = -1;
      goto cleanup;
    }

  xml_dir_created = TRUE;

  if (get_ignore_pagination.details)
    {
      /*
       * Populate the per-host compliance hash tables used by
       * print_report_hosts_xml().
       */
      ret = fill_filtered_audit_report_hosts (
        &result_hosts,
        &get_ignore_pagination,
        report,
        &results,
        &ctx,
        host_filter);

      if (ret)
        goto cleanup;

      results_initialized = 1;
    }

  xml_file = g_strdup_printf ("%s/audit-report-hosts.xml", xml_dir);

  stream = fopen (xml_file, "w");
  if (stream == NULL)
    {
      g_warning ("%s: Failed to open XML file: %s",
                 __func__,
                 strerror (errno));
      ret = -1;
      goto cleanup;
    }

  ret = print_report_hosts_xml (&ctx,
                                stream,
                                report,
                                &get_ignore_pagination,
                                "audit",
                                lean,
                                FALSE,
                                result_hosts_only,
                                host_filter,
                                result_hosts,
                                NULL,
                                TRUE);

  if (fclose (stream))
    {
      stream = NULL;
      g_warning ("%s: Failed to close XML file: %s",
                 __func__,
                 strerror (errno));
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
      g_warning ("%s: Failed to reopen XML file: %s",
                 __func__,
                 strerror (errno));
      ret = -1;
      goto cleanup;
    }

  while (1)
    {
      size_t bytes_read;

      bytes_read = fread (chunk,
                          1,
                          MANAGE_SEND_REPORT_CHUNK_SIZE,
                          stream);

      if (ferror (stream))
        {
          g_warning ("%s: Error reading XML file", __func__);
          ret = -1;
          goto cleanup;
        }

      if (bytes_read > 0)
        {
          chunk[bytes_read] = '\0';

          if (send (chunk, send_data_1, send_data_2))
            {
              g_warning ("%s: Send error", __func__);
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
  g_free (host_filter);

  print_report_context_cleanup (&ctx);

  if (xml_dir_created)
    gvm_file_remove_recurse (xml_dir);

  return ret;
}
