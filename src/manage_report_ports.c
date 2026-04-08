/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report ports.
 *
 * Non-SQL report ports code for the GVM management layer.
 */

#include "manage_report_ports.h"
#include "manage_filters.h"
#include "manage_sql_report_ports.h"

#include <util/fileutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Send report ports XML to the client.
 *
 * @param[in]  report                        Report.
 * @param[in]  get                           GET command data.
 * @param[in]  usage_type                    Task usage type.
 * @param[in]  send                          Function to write to client.
 * @param[in]  send_data_1                   Second argument to @p send.
 * @param[in]  send_data_2                   Third argument to @p send.
 * @param[in,out]  filtered_count            Filtered port count.
 *
 * @return 0 on success, -1 on error, 2 if filter was not found.
 */
int
manage_send_report_ports (report_t report,
                          const get_data_t *get,
                          const gchar *usage_type,
                          gboolean (*send) (const char *,
                                            int (*) (const char *, void *),
                                            void *),
                          int (*send_data_1) (const char *, void *),
                          void *send_data_2,
                          int *filtered_count)
{
  print_report_context_t ctx;
  gchar *xml_file;
  gchar *term;
  gchar *sort_field;
  gchar *levels;
  gchar *delta_states;
  gchar *search_phrase;
  char xml_dir[] = "/tmp/gvmd_XXXXXX";
  gboolean xml_dir_created = FALSE;
  char chunk[MANAGE_SEND_REPORT_CHUNK_SIZE + 1];
  FILE *stream;
  int ret;
  iterator_t results;
  int first_result;
  int max_results;
  int sort_order;

  memset (&ctx, 0, sizeof (ctx));
  term = NULL;
  sort_field = NULL;
  levels = NULL;
  delta_states = NULL;
  search_phrase = NULL;
  xml_file = NULL;
  stream = NULL;

  if (get == NULL)
    {
      g_warning ("%s: get is NULL", __func__);
      return -1;
    }

  ctx.get = get;
  ctx.report = report;
  ctx.tsk_usage_type = g_strdup (usage_type);

  ret = manage_report_filter_controls_from_get (get,
                                                &term,
                                                &first_result,
                                                &max_results,
                                                &sort_field,
                                                &sort_order,
                                                NULL,
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

  print_report_init_f_hosts (&ctx);

  // Initialize host_ports
  ctx.f_host_ports = g_hash_table_new_full (g_str_hash, g_str_equal,
                                            g_free, NULL);

  if (mkdtemp (xml_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed", __func__);
      ret = -1;
      goto cleanup;
    }

  xml_dir_created = TRUE;

  xml_file = g_strdup_printf ("%s/report-ports.xml", xml_dir);
  stream = fopen (xml_file, "w");
  if (stream == NULL)
    {
      g_warning ("%s: %s", __func__, strerror (errno));
      ret = -1;
      goto cleanup;
    }

  ret = print_report_port_xml_summary_or_details (&ctx,
                                                  report,
                                                  stream,
                                                  get,
                                                  get->details,
                                                  first_result,
                                                  max_results,
                                                  sort_order,
                                                  sort_field,
                                                  &results,
                                                  filtered_count);

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

  g_free (xml_file);
  g_free (term);
  g_free (sort_field);
  g_free (levels);
  g_free (delta_states);
  g_free (search_phrase);

  print_report_context_cleanup (&ctx);

  if (xml_dir_created)
    gvm_file_remove_recurse (xml_dir);

  return ret;
}