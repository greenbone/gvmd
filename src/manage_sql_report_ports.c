/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report ports.
 *
 * SQL handlers for report port XML.
 */

#include "manage_sql_report_ports.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Some result info, for sorting.
 */
struct result_buffer
{
  gchar *host;                  ///< Host.
  gchar *port;                  ///< Port.
  gchar *severity;              ///< Severity.
  double severity_double;       ///< Severity.
};

/**
 * @brief Buffer host type.
 */
typedef struct result_buffer result_buffer_t;

/**
 * @brief Create a result buffer.
 *
 * @param[in]  host      Host.
 * @param[in]  port      Port.
 * @param[in]  severity  Severity.
 * @param[in]  severity_double  Severity.
 *
 * @return Freshly allocated result buffer.
 */
static result_buffer_t*
result_buffer_new (const gchar *host, const gchar *port, const gchar *severity,
                   double severity_double)
{
  result_buffer_t *result_buffer;
  result_buffer = g_malloc (sizeof (result_buffer_t));
  result_buffer->host = g_strdup (host);
  result_buffer->port = g_strdup (port);
  result_buffer->severity = g_strdup (severity);
  result_buffer->severity_double = severity_double;
  return result_buffer;
}

/**
 * @brief Free a result buffer.
 *
 * @param[in]  result_buffer  Result buffer.
 */
static void
result_buffer_free (result_buffer_t *result_buffer)
{
  g_free (result_buffer->host);
  g_free (result_buffer->port);
  g_free (result_buffer->severity);
  g_free (result_buffer);
}

/**
 * @brief Compares two textual port representations, sorting descending
 * @brief by severity
 *
 * @param[in]  arg_one  First threat level.
 * @param[in]  arg_two  Second threat level.
 *
 * @return 1, 0 or -1 if first given severity is less than, equal to or greater
 *         than second.
 */
static gint
compare_severity_desc (gconstpointer arg_one, gconstpointer arg_two)
{
  double one_severity, two_severity;
  gchar *one = *((gchar**) arg_one);
  gchar *two = *((gchar**) arg_two);
  gint host;

  one += strlen (one) + 1;
  two += strlen (two) + 1;
  one_severity = g_strtod (one, NULL);
  two_severity = g_strtod (two, NULL);

  one += strlen (one) + 1;
  two += strlen (two) + 1;
  host = strcmp (one, two);
  if (host == 0)
    {
      if (one_severity > two_severity)
        return -1;
      else if (one_severity < two_severity)
        return 1;
      else
        {
          one = *((gchar**) arg_one);
          two = *((gchar**) arg_two);
          return strcmp (two, one);
        }
    }
  return host;
}

/**
 * @brief Compares two textual port representations, sorting descending
 * @brief by severity
 *
 * @param[in]  arg_one  First port.
 * @param[in]  arg_two  Second port.
 *
 * @return -1, 0 or 1 if first given severity is less than, equal to or greater
 *         than second.
 */
static gint
compare_severity_asc (gconstpointer arg_one, gconstpointer arg_two)
{
  double one_severity, two_severity;
  gchar *one = *((gchar**) arg_one);
  gchar *two = *((gchar**) arg_two);
  gint host;

  one += strlen (one) + 1;
  two += strlen (two) + 1;
  one_severity = g_strtod (one, NULL);
  two_severity = g_strtod (two, NULL);

  one += strlen (one) + 1;
  two += strlen (two) + 1;
  host = strcmp (one, two);
  if (host == 0)
    {
      if (one_severity < two_severity)
        return -1;
      else if (one_severity > two_severity)
        return 1;
      else
        {
          one = *((gchar**) arg_one);
          two = *((gchar**) arg_two);
          return strcmp (one, two);
        }
    }
  return host;
}

/**
 * @brief Compares two buffered results, sorting by host, port then severity.
 *
 * @param[in]  arg_one  First result.
 * @param[in]  arg_two  Second result.
 *
 * @return -1, 0 or 1 if first given result is less than, equal to or greater
 *         than second.
 */
static gint
compare_port_severity (gconstpointer arg_one, gconstpointer arg_two)
{
  int host;
  result_buffer_t *one, *two;

  one = *((result_buffer_t**) arg_one);
  two = *((result_buffer_t**) arg_two);

  host = strcmp (one->host, two->host);
  if (host == 0)
    {
      double severity_cmp;
      int port;

      port = strcmp (one->port, two->port);
      if (port != 0)
        return port;

      severity_cmp = two->severity_double - one->severity_double;
      if (severity_cmp > 0)
        return 1;
      else if (severity_cmp < 0)
        return -1;
      else
        return 0;
    }
  return host;
}

/**
 * @brief Count a report's total number of tcp/ip ports.
 *
 * Ignores port entries in "general/..." form.
 *
 * @param[in]  report  Report.
 *
 * @return Ports count.
 */
static int
report_port_count (report_t report)
{
  return sql_int ("SELECT count (DISTINCT port) FROM results"
                  " WHERE report = %llu AND port != ''"
                  "  AND port NOT %s 'general/%%';",
                  report,
                  sql_ilike_op ());
}

/**
 * @brief Print the XML for a report port summary to a file.
 *
 * @param[in]  ctx              Printing context.
 * @param[in]  report           The report.
 * @param[in]  out              File stream.
 * @param[in]  get              Result get data.
 * @param[in]  first_result     The result to start from.  The results are 0
 *                              indexed.
 * @param[in]  max_results      The maximum number of results returned.
 * @param[in]  sort_order       Whether to sort ascending or descending.
 * @param[in]  sort_field       Field to sort on.
 * @param[in,out] results       Result iterator.  For caller to reuse.
 *
 * @return 0 on success, -1 error.
 */
int
print_report_port_xml (print_report_context_t *ctx, report_t report, FILE *out,
                       const get_data_t *get, int first_result, int max_results,
                       int sort_order, const char *sort_field,
                       iterator_t *results)
{
  result_buffer_t *last_item;
  GArray *ports = g_array_new (TRUE, FALSE, sizeof (gchar*));

  init_result_get_iterator (results, get, report, NULL, NULL);

  /* Buffer the results, removing duplicates. */

  last_item = NULL;
  while (next (results))
    {
      const char *port = result_iterator_port (results);
      const char *host = result_iterator_host (results);
      double cvss_double;

      cvss_double = result_iterator_severity_double (results);

      if (last_item
          && strcmp (port, last_item->port) == 0
          && strcmp (host, last_item->host) == 0
          && last_item->severity_double <= cvss_double)
        {
          last_item->severity_double = cvss_double;
          g_free (last_item->severity);
          last_item->severity = g_strdup (result_iterator_severity (results));
        }
      else
        {
          const char *cvss;
          result_buffer_t *item;

          cvss = result_iterator_severity (results);
          if (cvss == NULL)
            {
              cvss_double = 0.0;
              cvss = "0.0";
            }
          item = result_buffer_new (host, port, cvss, cvss_double);
          g_array_append_val (ports, item);
          last_item = item;
        }

    }

  /* Handle sorting by threat and ROWID. */

  if (sort_field == NULL || strcmp (sort_field, "port"))
    {
      int index, length;

      /** @todo Sort by ROWID if was requested. */

      /* Sort by port then severity. */

      g_array_sort (ports, compare_port_severity);

      /* Remove duplicates. */

      last_item = NULL;
      for (index = 0, length = ports->len; index < length; index++)
        {
          result_buffer_t *item;

          item = g_array_index (ports, result_buffer_t*, index);
          if (last_item
              && (strcmp (item->port, last_item->port) == 0)
              && (strcmp (item->host, last_item->host) == 0))
            {
              if (item->severity_double > last_item->severity_double)
                {
                  gchar *severity;
                  severity = last_item->severity;
                  last_item->severity = item->severity;
                  item->severity = severity;
                  last_item->severity_double = item->severity_double;
                }
              g_array_remove_index (ports, index);
              length = ports->len;
              index--;
            }
          else
            last_item = item;
        }

      /* Sort by severity. */

      if (sort_order)
        g_array_sort (ports, compare_severity_asc);
      else
        g_array_sort (ports, compare_severity_desc);
    }

  /* Write to file from the buffer. */

  PRINT (out,
           "<ports"
           " start=\"%i\""
           " max=\"%i\">"
           "<count>%i</count>",
           /* Add 1 for 1 indexing. */
           first_result + 1,
           max_results,
           report_port_count (report));
  {
    result_buffer_t *item;
    int index = 0;

    while ((item = g_array_index (ports, result_buffer_t*, index++)))
      {
        int port_count;

        port_count = GPOINTER_TO_INT (g_hash_table_lookup (ctx->f_host_ports,
                                                           item->host));

        PRINT (out,
               "<port>"
               "<host>%s</host>"
               "%s"
               "<severity>%1.1f</severity>"
               "<threat>%s</threat>"
               "</port>",
               item->host,
               item->port,
               item->severity_double,
               severity_to_level (g_strtod (item->severity, NULL), 0));

        if (g_str_has_prefix(item->port, "general/") == FALSE)
          {
            g_hash_table_replace (ctx->f_host_ports,
                                  g_strdup (item->host),
                                  GINT_TO_POINTER (port_count + 1));
          }
        result_buffer_free (item);
      }
    g_array_free (ports, TRUE);
  }
  PRINT (out, "</ports>");

  return 0;
}