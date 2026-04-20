/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report hosts.
 *
 * SQL handlers for report host XML.
 */

#undef _XOPEN_SOURCE
/**
 * @brief Enable extra functions.
 *
 * For strptime in time.h.
 */
#define _XOPEN_SOURCE

#include "manage_sql_report_hosts.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Get the name from a report host details iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the report host detail. Caller must use only before
 *         calling cleanup_iterator.
 */
DEF_ACCESS (report_host_details_iterator_name, 1);

/**
 * @brief Get the value from a report host details iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the report host detail. Caller must use only before
 *         calling cleanup_iterator.
 */
DEF_ACCESS (report_host_details_iterator_value, 2);

/**
 * @brief Get the source type from a report host details iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source type of the report host detail. Caller must use only
 *         before calling cleanup_iterator.
 */
static
DEF_ACCESS (report_host_details_iterator_source_type, 3);

/**
 * @brief Get the source name from a report host details iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source name of the report host detail. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_host_details_iterator_source_name, 4);

/**
 * @brief Get the source description from a report host details iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source description of the report host detail. Caller must use
 *         only before calling cleanup_iterator.
 */
static
DEF_ACCESS (report_host_details_iterator_source_desc, 5);

/**
 * @brief Get the extra info from a report host details iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Extra info of the report host detail. Caller must use only before
 *         calling cleanup_iterator.
 */
static
DEF_ACCESS (report_host_details_iterator_extra, 6);

/**
 * @brief Get the hostname from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The hostname of the host.
 */
DEF_ACCESS (host_iterator_hostname, 6);

/**
 * @brief Get the asset UUID from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The UUID of the asset associated with the host. Caller must use
 *         only before calling cleanup_iterator.
 */
static
DEF_ACCESS (host_iterator_asset_uuid, 9);

/**
 * @brief Maximum severity information for a host.
 */
typedef struct
{
  double severity_double; ///< Numeric severity value.
  gchar *severity;        ///< Severity string representation.
} host_max_severity_t;

/**
 * @brief Free a host maximum severity entry.
 *
 * @param[in]  data  Host maximum severity entry.
 */
void
host_max_severity_free (gpointer data)
{
  host_max_severity_t *item = data;

  if (item == NULL)
    return;

  g_free (item->severity);
  g_free (item);
}

/**
 * @brief Create a new host maximum severity entry.
 *
 * @param[in]  severity_double  Numeric severity value.
 * @param[in]  severity         Severity string representation.
 *
 * @return Newly allocated host maximum severity entry.
 */
static host_max_severity_t *
host_max_severity_new (double severity_double, const char *severity)
{
  host_max_severity_t *item;

  item = g_malloc0 (sizeof (*item));
  item->severity_double = severity_double;
  item->severity = g_strdup (severity ? severity : "");

  return item;
}

/**
 * @brief Update maximum severity information for a host.
 *
 * @param[in,out]  ctx       Report print context holding per-host severity data.
 * @param[in]      results   Result iterator positioned at the current result.
 * @param[in]      host_key  Key identifying the host for aggregation.
 */
static void
update_filtered_host_max_severity (print_report_context_t *ctx,
                                   iterator_t *results,
                                   const gchar *host_key)
{
  host_max_severity_t *item;
  double cvss_double;
  const char *severity;

  if (ctx == NULL || results == NULL || host_key == NULL)
    return;

  cvss_double = result_iterator_severity_double (results);
  severity = result_iterator_severity (results);

  item = g_hash_table_lookup (ctx->f_host_max_severity, host_key);

  if (item == NULL)
    {
      item = host_max_severity_new (cvss_double, severity);

      g_hash_table_replace (ctx->f_host_max_severity,
                            g_strdup (host_key),
                            item);
    }
  else if (item->severity_double <= cvss_double)
    {
      item->severity_double = cvss_double;
      g_free (item->severity);
      item->severity = g_strdup (severity ? severity : "");
    }
}

/**
 * @brief Get the number of applications for a report host.
 *
 * @param[in]  report_host  Report host.
 *
 * @return Number of application entries for the report host.
 */
static int
report_host_app_count (report_host_t report_host)
{
  return sql_int_ps ("SELECT count(*) FROM report_host_details"
                     " WHERE report_host = $1"
                     "   AND name = 'App';",
                     SQL_RESOURCE_PARAM (report_host),
                     NULL);
}

/**
 * @brief Write report host detail to file stream.
 *
 * @param[in]  stream   Stream to write to.
 * @param[in]  details  Report host details iterator.
 * @param[in]  lean     Whether to return reduced info.
 *
 * @return 0 success, -1 error.
 */
static int
print_report_host_detail (FILE *stream, iterator_t *details, int lean)
{
  const char *name, *value;

  name = report_host_details_iterator_name (details);
  value = report_host_details_iterator_value (details);

  if (lean)
    {
      if (strcmp (name, "EXIT_CODE") == 0
          && strcmp (value, "EXIT_NOTVULN") == 0)
        return 0;

      if (strcmp (name, "scanned_with_scanner") == 0)
        return 0;

      if (strcmp (name, "scanned_with_feedtype") == 0)
        return 0;

      if (strcmp (name, "scanned_with_feedversion") == 0)
        return 0;

      if (strcmp (name, "OS") == 0)
        return 0;

      if (strcmp (name, "traceroute") == 0)
        return 0;
    }

  PRINT (stream,
         "<detail>"
         "<name>%s</name>"
         "<value>%s</value>"
         "<source>",
         name,
         value);

  if (lean == 0)
    PRINT (stream,
         "<type>%s</type>",
         report_host_details_iterator_source_type (details));

  PRINT (stream,
         "<name>%s</name>",
         report_host_details_iterator_source_name (details));

  if (report_host_details_iterator_source_desc (details)
      && strlen (report_host_details_iterator_source_desc (details)))
    PRINT (stream,
         "<description>%s</description>",
         report_host_details_iterator_source_desc (details));
  else if (lean == 0)
    PRINT (stream,
         "<description></description>");

  PRINT (stream, "</source>");

  if (report_host_details_iterator_extra (details)
      && strlen (report_host_details_iterator_extra (details)))
    PRINT (stream,
         "<extra>%s</extra>",
         report_host_details_iterator_extra (details));
  else if (lean == 0)
    PRINT (stream,
         "<extra></extra>");

  PRINT (stream, "</detail>");

  return 0;
}

/**
 * @brief Print the XML for a report host's details to a file stream.
 *
 * @param[in]  report_host  The report host.
 * @param[in]  stream       File stream to write to.
 * @param[in]  lean         Whether to return reduced info.
 *
 * @return 0 on success, -1 error.
 */
static int
print_report_host_details_xml (report_host_t report_host, FILE *stream,
                               int lean)
{
  iterator_t details;

  init_report_host_details_iterator (&details, report_host);
  while (next (&details))
    {
      if (print_report_host_detail (stream, &details, lean))
        {
          cleanup_iterator (&details);
          return -1;
        }
    }
  cleanup_iterator (&details);

  return 0;
}

/**
 * @brief Append one host summary line.
 *
 * @param[in]  host_summary_buffer  Summary buffer.
 * @param[in]  host                 Host.
 * @param[in]  start_iso            Start time in ISO format.
 * @param[in]  end_iso              End time in ISO format.
 */
static void
host_summary_append (GString *host_summary_buffer, const char *host,
                     const char *start_iso, const char *end_iso)
{
  if (host_summary_buffer)
    {
      char start[200], end[200];

      if (start_iso)
        {
          struct tm start_tm;

          memset (&start_tm, 0, sizeof (struct tm));
#if !defined(__GLIBC__)
          if (strptime (start_iso, "%Y-%m-%dT%H:%M:%S", &start_tm) == NULL)
#else
          if (strptime (start_iso, "%FT%H:%M:%S", &start_tm) == NULL)
#endif
            {
              g_warning ("%s: Failed to parse start", __func__);
              return;
            }

          if (strftime (start, sizeof (start), "%b %d, %H:%M:%S",
                        &start_tm) == 0)
            {
              g_warning ("%s: Failed to format start", __func__);
              return;
            }
        }
      else
        strcpy (start, "(not started)");

      if (end_iso)
        {
          struct tm end_tm;

          memset (&end_tm, 0, sizeof (struct tm));
#if !defined(__GLIBC__)
          if (strptime (end_iso, "%Y-%m-%dT%H:%M:%S", &end_tm) == NULL)
#else
          if (strptime (end_iso, "%FT%H:%M:%S", &end_tm) == NULL)
#endif
            {
              g_warning ("%s: Failed to parse end", __func__);
              return;
            }

          if (strftime (end, sizeof (end), "%b %d, %H:%M:%S", &end_tm) == 0)
            {
              g_warning ("%s: Failed to format end", __func__);
              return;
            }
        }
      else
        strcpy (end, "(not finished)");

      g_string_append_printf (host_summary_buffer,
                              "   %-15s   %-16s   %s\n",
                              host,
                              start,
                              end);
    }
}

/**
 * @brief Print the XML for a report's host to a file stream.
 *
 * @param[in]  ctx                  Printing context.
 * @param[in]  stream               File stream to write to.
 * @param[in]  hosts                Host iterator.
 * @param[in]  host                 Single host override, or NULL.
 * @param[in]  usage_type           Report usage type.
 * @param[in]  lean                 Whether to return lean report.
 * @param[in]  host_summary_buffer  Host summary buffer.
 * @param[in]  is_get_report_hosts  Whether called from get_report_hosts.
 *
 * @return 0 on success, -1 error.
 */
static int
print_report_host_xml (print_report_context_t *ctx,
                       FILE *stream,
                       iterator_t *hosts,
                       const char *host,
                       gchar *usage_type,
                       int lean,
                       GString *host_summary_buffer,
                       gboolean is_get_report_hosts)
{
  const char *current_host;
  int ports_count;
  host_max_severity_t *max_severity = NULL;

  current_host = host_iterator_host (hosts);

  ports_count
    = GPOINTER_TO_INT
    (g_hash_table_lookup (ctx->f_host_ports, current_host));

  host_summary_append (host_summary_buffer,
                       host ? host : host_iterator_host (hosts),
                       host_iterator_start_time (hosts),
                       host_iterator_end_time (hosts));

  PRINT (stream,
         "<host>"
         "<ip>%s</ip>",
         host ? host : host_iterator_host (hosts));

  if (host_iterator_asset_uuid (hosts)
      && strlen (host_iterator_asset_uuid (hosts)))
    PRINT (stream,
         "<asset asset_id=\"%s\"/>",
         host_iterator_asset_uuid (hosts));
  else if (lean == 0)
    PRINT (stream,
         "<asset asset_id=\"\"/>");

  if (strcmp (usage_type, "audit") == 0)
    {
      int yes_count, no_count, incomplete_count, undefined_count;

      yes_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_compliant, current_host));
      no_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_notcompliant, current_host));
      incomplete_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_incomplete, current_host));
      undefined_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_undefined, current_host));

      PRINT (stream,
             "<start>%s</start>"
             "<end>%s</end>"
             "<port_count><page>%d</page></port_count>"
             "<compliance_count>"
             "<page>%d</page>"
             "<yes><page>%d</page></yes>"
             "<no><page>%d</page></no>"
             "<incomplete><page>%d</page></incomplete>"
             "<undefined><page>%d</page></undefined>"
             "</compliance_count>"
             "<host_compliance>%s</host_compliance>",
             host_iterator_start_time (hosts),
             host_iterator_end_time (hosts)
             ? host_iterator_end_time (hosts)
             : "",
             ports_count,
             (yes_count + no_count + incomplete_count + undefined_count),
             yes_count,
             no_count,
             incomplete_count,
             undefined_count,
             report_compliance_from_counts (&yes_count,
               &no_count,
               &incomplete_count,
               &undefined_count));
    }
  else
    {
      int holes_count, warnings_count, infos_count;
      int logs_count, false_positives_count;
      int criticals_count = 0;

      criticals_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_criticals, current_host));
      holes_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_holes, current_host));
      warnings_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_warnings, current_host));
      infos_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_infos, current_host));
      logs_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_logs, current_host));
      false_positives_count
        = GPOINTER_TO_INT
        (g_hash_table_lookup (ctx->f_host_false_positives,
          current_host));

      PRINT (stream,
             "<start>%s</start>"
             "<end>%s</end>"
             "<port_count><page>%d</page></port_count>"
             "<result_count>"
             "<page>%d</page>"
             "<critical><page>%d</page></critical>"
             "<hole deprecated='1'><page>%d</page></hole>"
             "<high><page>%d</page></high>"
             "<warning deprecated='1'><page>%d</page></warning>"
             "<medium><page>%d</page></medium>"
             "<info deprecated='1'><page>%d</page></info>"
             "<low><page>%d</page></low>"
             "<log><page>%d</page></log>"
             "<false_positive><page>%d</page></false_positive>"
             "</result_count>",
             host_iterator_start_time (hosts),
             host_iterator_end_time (hosts)
             ? host_iterator_end_time (hosts)
             : "",
             ports_count,
             (criticals_count + holes_count + warnings_count + infos_count
               + logs_count + false_positives_count),
             criticals_count,
             holes_count,
             holes_count,
             warnings_count,
             warnings_count,
             infos_count,
             infos_count,
             logs_count,
             false_positives_count);
    }

  if (is_get_report_hosts)
    {
      /* get_report_hosts: print severity/threat instead of host details */
      max_severity = g_hash_table_lookup (ctx->f_host_max_severity,
                                          current_host);
      int apps_count =
        report_host_app_count (host_iterator_report_host (hosts));
      if (max_severity)
        PRINT (stream,
             "<app_count><page>%d</page></app_count>"
             "<severity>%1.1f</severity>"
             "<threat>%s</threat>",
             apps_count,
             max_severity->severity_double,
             severity_to_level (g_strtod (max_severity->severity, NULL), 0));
    }
  else
    {
      if (print_report_host_details_xml (host_iterator_report_host (hosts),
                                         stream,
                                         lean))
        return -1;
    }

  PRINT (stream, "</host>");

  return 0;
}

#if ENABLE_CONTAINER_SCANNING
/**
 * @brief Print the XML for a container scan report host to a file stream.
 *
 * @param[in]  ctx                  Printing context.
 * @param[in]  stream               File stream to write to.
 * @param[in]  hosts                Host iterator.
 * @param[in]  lean                 Whether to return lean report.
 * @param[in]  host_summary_buffer  Host summary buffer.
 * @param[in]  is_get_report_hosts  Whether called from get_report_hosts.
 *
 * @return 0 on success, -1 error.
 */
static int
print_container_scan_report_host_xml (print_report_context_t *ctx,
                                      FILE *stream,
                                      iterator_t *hosts,
                                      int lean,
                                      GString *host_summary_buffer,
                                      gboolean is_get_report_hosts)
{
  int ports_count;
  const char *host;
  const char *hostname;
  gchar *host_key;
  host_max_severity_t *max_severity = NULL;

  int holes_count, warnings_count, infos_count;
  int logs_count, false_positives_count;
  int criticals_count = 0;

  host = host_iterator_host (hosts);
  hostname = host_iterator_hostname (hosts);

  host_key = create_host_key (host,
                              hostname,
                              CONTAINER_SCANNER_HOST_KEY_SEPARATOR);

  ports_count
    = GPOINTER_TO_INT
    (g_hash_table_lookup (ctx->f_host_ports, host_key));

  host_summary_append (host_summary_buffer,
                       host,
                       host_iterator_start_time (hosts),
                       host_iterator_end_time (hosts));

  PRINT (stream,
         "<host>"
         "<ip>%s</ip>",
         host);

  if (host_iterator_asset_uuid (hosts)
      && strlen (host_iterator_asset_uuid (hosts)))
    PRINT (stream,
         "<asset asset_id=\"%s\"/>",
         host_iterator_asset_uuid (hosts));
  else if (lean == 0)
    PRINT (stream,
         "<asset asset_id=\"\"/>");

  criticals_count
    = GPOINTER_TO_INT
    (g_hash_table_lookup (ctx->f_host_criticals, host_key));
  holes_count
    = GPOINTER_TO_INT
    (g_hash_table_lookup (ctx->f_host_holes, host_key));
  warnings_count
    = GPOINTER_TO_INT
    (g_hash_table_lookup (ctx->f_host_warnings, host_key));
  infos_count
    = GPOINTER_TO_INT
    (g_hash_table_lookup (ctx->f_host_infos, host_key));
  logs_count
    = GPOINTER_TO_INT
    (g_hash_table_lookup (ctx->f_host_logs, host_key));
  false_positives_count
    = GPOINTER_TO_INT
    (g_hash_table_lookup (ctx->f_host_false_positives, host_key));

  PRINT (stream,
         "<start>%s</start>"
         "<end>%s</end>"
         "<port_count><page>%d</page></port_count>"
         "<result_count>"
         "<page>%d</page>"
         "<critical><page>%d</page></critical>"
         "<hole deprecated='1'><page>%d</page></hole>"
         "<high><page>%d</page></high>"
         "<warning deprecated='1'><page>%d</page></warning>"
         "<medium><page>%d</page></medium>"
         "<info deprecated='1'><page>%d</page></info>"
         "<low><page>%d</page></low>"
         "<log><page>%d</page></log>"
         "<false_positive><page>%d</page></false_positive>"
         "</result_count>",
         host_iterator_start_time (hosts),
         host_iterator_end_time (hosts)
         ? host_iterator_end_time (hosts)
         : "",
         ports_count,
         (criticals_count + holes_count + warnings_count + infos_count
           + logs_count + false_positives_count),
         criticals_count,
         holes_count,
         holes_count,
         warnings_count,
         warnings_count,
         infos_count,
         infos_count,
         logs_count,
         false_positives_count);

  if (is_get_report_hosts)
    {
      /* get_report_hosts: print severity/threat instead of host details */
      max_severity = g_hash_table_lookup (ctx->f_host_max_severity,
                                          host_key);
      /* application info is not included in container scanning host details
       * for consistency always returns 0.
       */
      if (max_severity)
        PRINT (stream,
             "<app_count><page>0</page></app_count>"
             "<severity>%1.1f</severity>"
             "<threat>%s</threat>",
             max_severity->severity_double,
             severity_to_level (g_strtod (max_severity->severity, NULL), 0));
    }
  else
    {
      if (print_report_host_details_xml (host_iterator_report_host (hosts),
                                         stream,
                                         lean))
        {
          g_free (host_key);
          return -1;
        }
    }

  PRINT (stream, "</host>");

  g_free (host_key);

  return 0;
}

/**
 * @brief Print all hosts from a container scan host iterator.
 *
 * @param[in]  ctx                  Printing context.
 * @param[in]  stream               File stream to write to.
 * @param[in]  hosts                Host iterator.
 * @param[in]  lean                 Whether to return lean report.
 * @param[in]  host_summary_buffer  Host summary buffer.
 * @param[in]  is_get_report_hosts  Whether called from get_report_hosts.
 *
 * @return 0 on success, -1 error.
 */
static int
print_container_scan_report_hosts_xml (print_report_context_t *ctx,
                                       FILE *stream,
                                       iterator_t *hosts,
                                       int lean,
                                       GString *host_summary_buffer,
                                       gboolean is_get_report_hosts)
{
  while (next (hosts))
    {
      if (print_container_scan_report_host_xml (ctx,
                                                stream,
                                                hosts,
                                                lean,
                                                host_summary_buffer,
                                                is_get_report_hosts))
        {
          g_warning ("%s: Failed to print host XML", __func__);
          return -1;
        }
    }

  return 0;
}
#endif /* ENABLE_CONTAINER_SCANNING */

/**
 * @brief Print report hosts XML.
 *
 * @param[in]  ctx                  Printing context.
 * @param[in]  stream               File stream to write to.
 * @param[in]  report               Report.
 * @param[in]  get                  GET data.
 * @param[in]  usage_type           Report usage type.
 * @param[in]  lean                 Whether to return lean report.
 * @param[in]  is_container_scan    Whether this is a container scan report.
 * @param[in]  result_hosts_only    Whether to print only hosts with results.
 * @param[in]  result_hosts         Result hosts array, used when result_hosts_only is set.
 * @param[in]  host_summary_buffer  Host summary buffer.
 * @param[in]  is_get_report_hosts  Whether called from get_report_hosts.
 *
 * @return 0 on success, -1 error.
 */
int
print_report_hosts_xml (print_report_context_t *ctx,
                        FILE *stream,
                        report_t report,
                        const get_data_t *get,
                        const gchar *usage_type,
                        int lean,
                        gboolean is_container_scan,
                        gboolean result_hosts_only,
                        array_t *result_hosts,
                        GString *host_summary_buffer,
                        gboolean is_get_report_hosts)
{
  if (get == NULL)
    {
      g_warning ("%s: get is NULL", __func__);
      return -1;
    }

  if (get->details == 0)
    {
      PRINT (stream,
             "<hosts><count>%i</count></hosts>",
             report_host_count (report));
      return 0;
    }

#if ENABLE_CONTAINER_SCANNING
  if (is_container_scan)
    {
      if (result_hosts_only)
        {
          gchar *result_host;
          int index = 0;

          if (result_hosts == NULL)
            {
              g_warning ("%s: result_hosts_only set but result_hosts is NULL",
                         __func__);
              return -1;
            }

          array_terminate (result_hosts);

          while ((result_host = g_ptr_array_index (result_hosts, index++)))
            {
              iterator_t hosts;
              gchar *host = NULL;
              gchar *hostname = NULL;

              if (parse_host_key (result_host,
                                  CONTAINER_SCANNER_HOST_KEY_SEPARATOR,
                                  &host,
                                  &hostname) < 0)
                {
                  g_warning ("%s: Failed to parse host key", __func__);
                  return -1;
                }

              init_report_host_iterator_hostname (
                &hosts, report, host, hostname);

              g_free (host);
              g_free (hostname);

              if (print_container_scan_report_hosts_xml (ctx,
                stream,
                &hosts,
                lean,
                host_summary_buffer,
                is_get_report_hosts))
                {
                  cleanup_iterator (&hosts);
                  return -1;
                }

              cleanup_iterator (&hosts);
            }

          return 0;
        }
      else
        {
          iterator_t hosts;

          init_report_host_iterator (&hosts, report, NULL, 0);

          if (print_container_scan_report_hosts_xml (ctx,
            stream,
            &hosts,
            lean,
            host_summary_buffer,
            is_get_report_hosts))
            {
              cleanup_iterator (&hosts);
              return -1;
            }

          cleanup_iterator (&hosts);
          return 0;
        }
    }
#endif /* ENABLE_CONTAINER_SCANNING */

  if (result_hosts_only)
    {
      gchar *result_host;
      int index = 0;

      if (result_hosts == NULL)
        {
          g_warning ("%s: result_hosts_only set but result_hosts is NULL",
                     __func__);
          return -1;
        }

      array_terminate (result_hosts);

      while ((result_host = g_ptr_array_index (result_hosts, index++)))
        {
          iterator_t hosts;
          gboolean present;

          init_report_host_iterator (&hosts, report, result_host, 0);
          present = next (&hosts);

          if (present)
            {
              if (print_report_host_xml (ctx,
                                         stream,
                                         &hosts,
                                         result_host,
                                         (gchar *) usage_type,
                                         lean,
                                         host_summary_buffer,
                                         is_get_report_hosts))
                {
                  cleanup_iterator (&hosts);
                  return -1;
                }
            }

          cleanup_iterator (&hosts);
        }

      return 0;
    }
  else
    {
      iterator_t hosts;

      init_report_host_iterator (&hosts, report, NULL, 0);

      while (next (&hosts))
        {
          if (print_report_host_xml (ctx,
                                     stream,
                                     &hosts,
                                     NULL,
                                     (gchar *) usage_type,
                                     lean,
                                     host_summary_buffer,
                                     is_get_report_hosts))
            {
              cleanup_iterator (&hosts);
              return -1;
            }
        }

      cleanup_iterator (&hosts);
      return 0;
    }
}

/**
 * @brief Update filtered per-host port counts in the report context.
 *
 * @param[in,out]  ctx              Report print context holding per-host port counts.
 * @param[in]      host_key         Key identifying the host for aggregation.
 * @param[in]      port             Port of the current result.
 * @param[in,out]  seen_host_ports  Set of already counted host/port pairs.
 */
static void
update_filtered_host_port_counts (print_report_context_t *ctx,
                                  const gchar *host_key,
                                  const gchar *port,
                                  GHashTable *seen_host_ports)
{
  gchar *host_port_key;
  int port_count;

  if (ctx == NULL || host_key == NULL || port == NULL || seen_host_ports ==
      NULL)
    return;

  if (*port == '\0')
    return;

  if (g_str_has_prefix (port, "general/"))
    return;

  host_port_key = g_strdup_printf ("%s|%s", host_key, port);

  if (g_hash_table_lookup (seen_host_ports, host_port_key))
    {
      g_free (host_port_key);
      return;
    }

  g_hash_table_add (seen_host_ports, host_port_key);

  port_count = GPOINTER_TO_INT (g_hash_table_lookup (ctx->f_host_ports,
    host_key));

  g_hash_table_replace (ctx->f_host_ports,
                        g_strdup (host_key),
                        GINT_TO_POINTER (port_count + 1));
}

/**
 * @brief Update filtered per-host result counts in the report context.
 *
 * @param[in,out] ctx       Report print context holding per-host count tables.
 * @param[in]     results   Result iterator positioned at the current result.
 * @param[in]     host_key  Key identifying the host for aggregation.
 */
static void
update_filtered_host_result_counts (print_report_context_t *ctx,
                                    iterator_t *results,
                                    const gchar *host_key)
{
  GHashTable *f_host_result_counts = NULL;
  const char *level;

  if (ctx == NULL || results == NULL || host_key == NULL)
    return;

  level = result_iterator_level (results);
  if (level == NULL)
    return;

  if (strcasecmp (level, "log") == 0)
    f_host_result_counts = ctx->f_host_logs;
  else if (strcasecmp (level, "critical") == 0)
    f_host_result_counts = ctx->f_host_criticals;
  else if (strcasecmp (level, "high") == 0)
    f_host_result_counts = ctx->f_host_holes;
  else if (strcasecmp (level, "medium") == 0)
    f_host_result_counts = ctx->f_host_warnings;
  else if (strcasecmp (level, "low") == 0)
    f_host_result_counts = ctx->f_host_infos;
  else if (strcasecmp (level, "false positive") == 0)
    f_host_result_counts = ctx->f_host_false_positives;

  if (f_host_result_counts)
    {
      int result_count;

      result_count = GPOINTER_TO_INT
        (g_hash_table_lookup (f_host_result_counts, host_key));

      g_hash_table_replace (f_host_result_counts,
                            g_strdup (host_key),
                            GINT_TO_POINTER (result_count + 1));
    }
}

/**
 * @brief Initialize the result iterator and collect all result hosts.
 *
 * @param[in, out] result_hosts Array to be filled with host keys (must be initialized).
 * @param[in]      get Request data used for iterator initialization.
 * @param[in]      report Report identifier.
 * @param[in, out] results Result iterator to use.
 * @param[in]      is_container_scanning_report Whether to generate
 *                                              container-aware host keys.
 * @param[in, out] ctx  Report print context used to store filtered per-host counts.
 * @param[in]      is_get_report_hosts  Whether called from get_report_hosts.
 *
 * @return 0 on success, non-zero on failure.
 */
int
fill_filtered_result_hosts (array_t **result_hosts,
                            const get_data_t *get,
                            report_t report,
                            iterator_t *results,
                            gboolean is_container_scanning_report,
                            print_report_context_t *ctx,
                            gboolean is_get_report_hosts)
{
  int ret;

  if (result_hosts == NULL)
    return -1;

  *result_hosts = make_array ();

  ret = init_result_get_iterator (results, get, report, NULL, NULL);
  if (ret)
    return ret;

  while (next (results))
    {
      gchar *host_key;

#if ENABLE_CONTAINER_SCANNING
      if (is_container_scanning_report)
        host_key = create_host_key (result_iterator_host (results),
                                    result_iterator_hostname (results),
                                    CONTAINER_SCANNER_HOST_KEY_SEPARATOR);
      else
#endif
        host_key = g_strdup (result_iterator_host (results));

      array_add_new_string (*result_hosts, host_key);

      if (ctx != NULL)
        {
          update_filtered_host_result_counts (ctx, results, host_key);
          update_filtered_host_port_counts (ctx,
                                            host_key,
                                            result_iterator_port (results),
                                            ctx->f_host_ports);

          if (is_get_report_hosts)
            update_filtered_host_max_severity (ctx, results, host_key);
        }
    }

  return 0;
}

/**
 * @brief Initialise a host iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report    Report whose hosts the iterator loops over.
 * @param[in]  host      Single host to iterate over.  All hosts if NULL.
 * @param[in]  report_host  Single report host to iterate over.  All if 0.
 */
void
init_report_host_iterator (iterator_t *iterator, report_t report,
                           const char *host,
                           report_host_t report_host)
{
  if (report)
    {
      init_ps_iterator (iterator,
                        "SELECT id, host, iso_time (start_time),"
                        " iso_time (end_time), current_port,"
                        " max_port, hostname, report,"
                        " (SELECT uuid FROM reports WHERE id = report),"
                        " (SELECT uuid FROM hosts"
                        "  WHERE id = (SELECT host FROM host_identifiers"
                        "              WHERE source_type = 'Report Host'"
                        "              AND name = 'ip'"
                        "              AND source_id = (SELECT uuid"
                        "                               FROM reports"
                        "                               WHERE id = report)"
                        "              AND value = report_hosts.host"
                        "              LIMIT 1))"
                        " FROM report_hosts"
                        " WHERE ($1 = 0 OR id = $1)"
                        "   AND report = $2"
                        "   AND ($3::text IS NULL OR host = $3)"
                        " ORDER BY order_inet (host);",
                        SQL_RESOURCE_PARAM (report_host),
                        SQL_RESOURCE_PARAM (report),
                        host ? SQL_STR_PARAM (host) : SQL_NULL_PARAM,
                        NULL);
    }
  else
    {
      init_ps_iterator (iterator,
                        "SELECT id, host, iso_time (start_time),"
                        " iso_time (end_time), current_port, max_port,"
                        " hostname, report,"
                        " (SELECT uuid FROM reports WHERE id = report),"
                        " ''"
                        " FROM report_hosts"
                        " WHERE ($1 = 0 OR id = $1)"
                        "   AND ($2::text IS NULL OR host = $2)"
                        " ORDER BY order_inet (host);",
                        SQL_RESOURCE_PARAM (report_host),
                        host ? SQL_STR_PARAM (host) : SQL_NULL_PARAM,
                        NULL);
    }
}

/**
 * @brief Initialise a host iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report    Report whose hosts the iterator loops over.
 * @param[in]  host      Host to iterate over.
 * @param[in]  hostname  Hostname.
 */
void
init_report_host_iterator_hostname (iterator_t *iterator,
                                    report_t report,
                                    const char *host,
                                    const char *hostname)
{
  init_ps_iterator (iterator,
                    "SELECT id, host, iso_time (start_time),"
                    " iso_time (end_time), current_port, max_port,"
                    " hostname, report,"
                    " (SELECT uuid FROM reports WHERE id = report),"
                    " (SELECT uuid FROM hosts"
                    "  WHERE id = (SELECT host FROM host_identifiers"
                    "              WHERE source_type = 'Report Host'"
                    "              AND name = 'ip'"
                    "              AND source_id = (SELECT uuid"
                    "                               FROM reports"
                    "                               WHERE id = report)"
                    "              AND value = report_hosts.host"
                    "              LIMIT 1))"
                    " FROM report_hosts"
                    " WHERE report = $1"
                    "   AND host = $2"
                    "   AND hostname = $3"
                    " ORDER BY order_inet (host);",
                    SQL_RESOURCE_PARAM (report),
                    SQL_STR_PARAM (host),
                    SQL_STR_PARAM (hostname),
                    NULL);
}

/**
 * @brief Get the report host from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Report host.
 */
report_host_t
host_iterator_report_host (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return (report_host_t) iterator_int64 (iterator, 0);
}

/**
 * @brief Get the host from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The host of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (host_iterator_host, 1);

/**
 * @brief Get the start time from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The start time of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (host_iterator_start_time, 2);

/**
 * @brief Get the end time from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The end time of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (host_iterator_end_time, 3);

/**
 * @brief Get the current port from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Current port.
 */
int
host_iterator_current_port (iterator_t *iterator)
{
  int ret;
  if (iterator->done)
    return -1;
  ret = iterator_int (iterator, 4);
  return ret;
}

/**
 * @brief Get the max port from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Current port.
 */
int
host_iterator_max_port (iterator_t *iterator)
{
  int ret;
  if (iterator->done)
    return -1;
  ret = iterator_int (iterator, 5);
  return ret;
}

/**
 * @brief Generates extra where condition for report hosts
 *
 * @param report_uuid Report uuid for Where condition
 *
 * @return Newly allocated where clause string.
 */
gchar *
report_hosts_extra_where (const gchar *report_uuid)
{
  gchar *extra_where;
  gchar *quoted_report_uuid = sql_quote (report_uuid);

  extra_where = g_strdup_printf (
    " AND report = (SELECT id from reports WHERE uuid = '%s')",
    quoted_report_uuid);

  g_free (quoted_report_uuid);

  return extra_where;
}
