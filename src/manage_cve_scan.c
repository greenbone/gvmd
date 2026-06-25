/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager CVE scan handling.
 */

#include "manage_cve_scan.h"

#include "manage.h"
#include "manage_sql.h"
#include "manage_sql_assets.h"

#include <util/cpeutils.h>
#include <util/versionutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/* CVE tasks. */

/**
 * @brief Check if version is in a given range.
 *
 * @param  target      Target version.
 * @param  start_incl  Start of range (inclusive), or NULL.
 * @param  start_excl  Start of range (exclusive), or NULL.
 * @param  end_incl    End of range (inclusive), or NULL.
 * @param  end_excl    End of range (exclusive), or NULL.
 *
 * @return 0 target is within given range, 1 target is outside given range,
 *         -1 result is undefined.
 */
static int
check_version (const gchar *target, const gchar *start_incl, const gchar *start_excl, const gchar *end_incl, const gchar *end_excl)
{
  int result;

  if (start_incl != NULL)
    {
      result = cmp_versions (start_incl, target);
      if (result == -5)
        return -1;
      if (result > 0)
        {
          return 0;
        }
    }
  if (start_excl != NULL)
    {
      result = cmp_versions (start_excl, target);
      if (result == -5)
        return -1;
      if (result >= 0)
        {
          return 0;
        }
    }

  if (end_incl != NULL)
    {
      result = cmp_versions (end_incl, target);
      if (result == -5)
        return -1;
      if (result < 0)
        {
          return 0;
        }
    }

  if (end_excl != NULL)
    {
      result = cmp_versions (end_excl, target);
      if (result == -5)
        return -1;
      if (result <= 0)
        {
          return 0;
        }
    }

  return (1);
}

/**
 * @brief Check CPE rule match.
 *
 * @param[in]  node         CPE match node.
 * @param[out] match        TRUE if matched.
 * @param[out] vulnerable   TRUE if vulnerable.
 * @param[in]  report_host  Report host to get CPEs from.
 * @param[in]  host_cpe     CPE being checked.
 */
static void
check_cpe_match_rule (long long int node, gboolean *match, gboolean *vulnerable, report_host_t report_host, const char *host_cpe)
{
  iterator_t cpe_match_node_childs;
  gchar *operator;
  iterator_t cpe_match_ranges;

  operator = sql_string ("SELECT operator FROM scap.cpe_match_nodes WHERE id = %llu", node);
  if (operator == NULL)
    return;
  init_cpe_match_node_childs_iterator (&cpe_match_node_childs, node);
  while (next (&cpe_match_node_childs))
    {
      long long int child_node;
      child_node = cpe_match_node_childs_iterator_id (&cpe_match_node_childs);
      check_cpe_match_rule (child_node, match, vulnerable, report_host, host_cpe);
      if (strcmp (operator, "AND") == 0 && !(*match))
        goto cleanup_node_childs;
      if (strcmp (operator, "OR") == 0 && (*match) && (*vulnerable))
        goto cleanup_node_childs;
    }

  init_cpe_match_string_iterator (&cpe_match_ranges, node);
  while (next (&cpe_match_ranges))
    {
      iterator_t cpe_host_details_products;
      gchar *range_uri_cpe;
      gchar *range_uri_product;
      gchar *vsi, *vse, *vei, *vee;
      range_uri_cpe = vsi = vse = vei = vee = NULL;
      range_uri_cpe = g_strdup (cpe_match_string_iterator_criteria (&cpe_match_ranges));
      vsi = g_strdup (cpe_match_string_iterator_version_start_incl (&cpe_match_ranges));
      vse = g_strdup (cpe_match_string_iterator_version_start_excl (&cpe_match_ranges));
      vei = g_strdup (cpe_match_string_iterator_version_end_incl (&cpe_match_ranges));
      vee = g_strdup (cpe_match_string_iterator_version_end_excl (&cpe_match_ranges));
      range_uri_product = uri_cpe_to_uri_product (range_uri_cpe);
      init_host_details_cpe_product_iterator (&cpe_host_details_products, range_uri_product, report_host);
      while (next (&cpe_host_details_products))
        {
          cpe_struct_t source, target;
          const char *host_details_cpe;
          gboolean matches;
          host_details_cpe = host_details_cpe_product_iterator_value (&cpe_host_details_products);
          cpe_struct_init (&source);
          cpe_struct_init (&target);
          uri_cpe_to_cpe_struct (range_uri_cpe, &source);
          uri_cpe_to_cpe_struct (host_details_cpe, &target);
          matches = cpe_struct_match (&source, &target);
          if (matches)
            {
              int result;
              result = check_version (target.version, vsi, vse, vei, vee);
              if (result == 1)
                *match = TRUE;
            }
          cpe_struct_free (&source);
          cpe_struct_free (&target);
        }
      cleanup_iterator (&cpe_host_details_products);
      if (*match && cpe_match_string_iterator_vulnerable (&cpe_match_ranges) == 1)
        {
          cpe_struct_t source, target;
          cpe_struct_init (&source);
          cpe_struct_init (&target);
          uri_cpe_to_cpe_struct (range_uri_cpe, &source);
          uri_cpe_to_cpe_struct (host_cpe, &target);
          if (cpe_struct_match (&source, &target))
            *vulnerable = TRUE;
          cpe_struct_free (&source);
          cpe_struct_free (&target);
        }
      g_free (range_uri_product);
      g_free (range_uri_cpe);
      g_free (vsi);
      g_free (vse);
      g_free (vei);
      g_free (vee);
      if (strcmp (operator, "AND") == 0 && !(*match))
        goto cleanup_ranges;
      if (strcmp (operator, "OR") == 0 && (*match) && (*vulnerable))
        goto cleanup_ranges;
    }
 cleanup_ranges:
  cleanup_iterator (&cpe_match_ranges);
 cleanup_node_childs:
  cleanup_iterator (&cpe_match_node_childs);
  g_free (operator);
}

/**
 * @brief Perform the json CVE "scan" for the found report host.
 *
 * @param[in]  task        Task.
 * @param[in]  report      The report to add the host, results and details to.
 * @param[in]  report_host The report host.
 * @param[in]  ip          The ip of the report host.
 * @param[in]  start_time  The start time of the scan.
 *
 * @param[out] prognosis_report_host  The report_host with prognosis results
 *                                    and host details.
 * @param[out] results                The results of the scan.
 */
static void
cve_scan_report_host_json (task_t task,
                           report_t report,
                           report_host_t report_host,
                           gchar *ip,
                           int start_time,
                           int *prognosis_report_host,
                           GArray *results)
{
  iterator_t host_details_cpe;
  init_host_details_cpe_iterator (&host_details_cpe, report_host);
  while (next (&host_details_cpe))
    {
      iterator_t cpe_match_root_node;
      iterator_t locations_iter;
      result_t result;
      char *cpe_product;
      const char *host_cpe;
      double severity;

      host_cpe = host_details_cpe_iterator_cpe (&host_details_cpe);
      cpe_product = uri_cpe_to_uri_product (host_cpe);
      init_cpe_match_nodes_iterator (&cpe_match_root_node, cpe_product);
      while (next (&cpe_match_root_node))
        {
          result_t root_node;
          gboolean match, vulnerable;

          vulnerable = FALSE;
          match = FALSE;
          root_node = cpe_match_nodes_iterator_root_id (&cpe_match_root_node);
          check_cpe_match_rule (root_node, &match, &vulnerable, report_host, host_cpe);
          if (match && vulnerable)
            {
              GString *locations;
              gchar *desc, *description, *cve;
              const char *app;

              if (*prognosis_report_host == 0)
                *prognosis_report_host = manage_report_host_add (report,
                                                                 ip,
                                                                 start_time,
                                                                 0);

              severity = sql_double ("SELECT severity FROM scap.cves, scap.cpe_match_nodes"
                                     " WHERE scap.cves.id = scap.cpe_match_nodes.cve_id"
                                     " AND scap.cpe_match_nodes.id = %llu;",
                                     root_node);

              app = host_cpe;
              cve = sql_string ("SELECT name FROM scap.cves, scap.cpe_match_nodes"
                                " WHERE scap.cves.id = cpe_match_nodes.cve_id"
                                " AND scap.cpe_match_nodes.id = %llu;",
                                root_node);
              locations = g_string_new ("");

              insert_report_host_detail (global_current_report, ip, "cve", cve,
                                         "CVE Scanner", "App", app, NULL);

              init_app_locations_iterator (&locations_iter, report_host, app);

              while (next (&locations_iter))
                {
                  const char *location;
                  location = app_locations_iterator_location (&locations_iter);

                  if (location == NULL)
                    {
                      g_warning ("%s: Location is null for ip %s, app %s",
                                 __func__, ip, app);
                      continue;
                    }

                  if (locations->len)
                    {
                      g_string_append (locations, ", ");
                    }
                  g_string_append (locations, location);

                  insert_report_host_detail (report, ip, "cve", cve,
                                             "CVE Scanner", app, location, NULL);

                  insert_report_host_detail (report, ip, "cve", cve,
                                             "CVE Scanner", "detected_at",
                                             location, NULL);

                  insert_report_host_detail (report, ip, "cve", cve,
                                             "CVE Scanner", "detected_by",
                                             /* Detected by itself. */
                                             cve, NULL);
                }
              cleanup_iterator (&locations_iter);

              description = sql_string ("SELECT description FROM scap.cves, scap.cpe_match_nodes"
                                        " WHERE scap.cves.id = scap.cpe_match_nodes.cve_id"
                                        " AND scap.cpe_match_nodes.id = %llu;",
                                        root_node);

              desc = g_strdup_printf ("The host carries the product: %s\n"
                                      "It is vulnerable according to: %s.\n"
                                      "%s%s%s"
                                      "\n"
                                      "%s",
                                      app,
                                      cve,
                                      locations->len
                                       ? "The product was found at: "
                                       : "",
                                      locations->len ? locations->str : "",
                                      locations->len ? ".\n" : "",
                                      description);

              g_free (description);

              g_debug ("%s: making result with severity %1.1f desc [%s]",
                       __func__, severity, desc);

              result = make_cve_result (task, ip, cve, severity, desc);
              g_free (cve);
              g_free (desc);

              g_array_append_val (results, result);

              g_string_free (locations, TRUE);

            }
        }
      cleanup_iterator (&cpe_match_root_node);
      g_free (cpe_product);
    }
  cleanup_iterator (&host_details_cpe);
}

/**
 * @brief Perform a CVE "scan" on a host.
 *
 * @param[in]  task      Task.
 * @param[in]  report    The report to add the host, results and details to.
 * @param[in]  gvm_host  Host.
 * @param[in]  matching_version  The CPE-CVE matching version (0 or 1) to use.
 *
 * With version 0 matching, CPEs are only compared to the affected products
 *  lists of CVEs.
 * With version 1 matching, CPEs are matched by evaluating the match criteria
 *  for the CVEs.
 *
 * @return 0 success, 1 failed to get nthlast report for a host.
 */
int
cve_scan_host (task_t task, report_t report, gvm_host_t *gvm_host,
               int matching_version)
{
  report_host_t report_host;
  gchar *ip;

  assert (task);
  assert (report);

  {
    gchar *host;

    host = gvm_host_value_str (gvm_host);

    ip = report_host_ip (host);
    if (ip == NULL)
      ip = g_strdup (host);

    g_free (host);
  }

  g_debug ("%s: ip: %s", __func__, ip);

  /* Get the last report host that applies to the host IP address. */

  if (host_nthlast_report_host (ip, &report_host, 1))
    {
      g_warning ("%s: Failed to get nthlast report", __func__);
      g_free (ip);
      return 1;
    }

  g_debug ("%s: report_host: %llu", __func__, report_host);

  if (report_host)
    {
      iterator_t report_hosts;

      /* Get the report_host for the host. */

      init_report_host_iterator (&report_hosts, 0, NULL, report_host);
      if (next (&report_hosts))
        {
          iterator_t prognosis;
          int prognosis_report_host, start_time;
          GArray *results;

          /* Add report_host with prognosis results and host details. */

          results = g_array_new (TRUE, TRUE, sizeof (result_t));
          start_time = time (NULL);
          prognosis_report_host = 0;

          if (matching_version == 1 &&
              sql_int64_0 ("SELECT count(1) FROM information_schema.tables"
                           " WHERE table_schema = 'scap'"
                           " AND table_name = 'cpe_match_nodes';") > 0)
            {
              // Use new JSON CVE scan
              cve_scan_report_host_json (task, report, report_host, ip,
                                         start_time, &prognosis_report_host,
                                         results);
            }
          else
            {
              // Use XML CVE scan
              init_host_prognosis_iterator (&prognosis, report_host);
              while (next (&prognosis))
                {
                  const char *app, *cve;
                  double severity;
                  gchar *desc;
                  iterator_t locations_iter;
                  GString *locations;
                  result_t result;

                  if (prognosis_report_host == 0)
                    prognosis_report_host = manage_report_host_add (report,
                                                                    ip,
                                                                    start_time,
                                                                    0);

                  severity = prognosis_iterator_cvss_double (&prognosis);

                  app = prognosis_iterator_cpe (&prognosis);
                  cve = prognosis_iterator_cve (&prognosis);
                  locations = g_string_new("");

                  insert_report_host_detail (global_current_report, ip, "cve", cve,
                                             "CVE Scanner", "App", app, NULL);

                  init_app_locations_iterator (&locations_iter, report_host, app);

                  while (next (&locations_iter))
                    {
                      const char *location;
                      location = app_locations_iterator_location (&locations_iter);

                      if (location == NULL)
                        {
                          g_warning ("%s: Location is null for ip %s, app %s",
                                     __func__, ip, app);
                          continue;
                        }

                      if (locations->len)
                        g_string_append (locations, ", ");
                      g_string_append (locations, location);

                      insert_report_host_detail (report, ip, "cve", cve,
                                                 "CVE Scanner", app, location, NULL);

                      insert_report_host_detail (report, ip, "cve", cve,
                                                 "CVE Scanner", "detected_at",
                                                 location, NULL);

                      insert_report_host_detail (report, ip, "cve", cve,
                                                 "CVE Scanner", "detected_by",
                                                 /* Detected by itself. */
                                                 cve, NULL);
                    }
                  cleanup_iterator (&locations_iter);

                  desc = g_strdup_printf ("The host carries the product: %s\n"
                                          "It is vulnerable according to: %s.\n"
                                          "%s%s%s"
                                          "\n"
                                          "%s",
                                          app,
                                          cve,
                                          locations->len
                                           ? "The product was found at: "
                                           : "",
                                          locations->len ? locations->str : "",
                                          locations->len ? ".\n" : "",
                                          prognosis_iterator_description
                                           (&prognosis));

                  g_debug ("%s: making result with severity %1.1f desc [%s]",
                           __func__, severity, desc);

                  result = make_cve_result (task, ip, cve, severity, desc);
                  g_free (desc);

                  g_array_append_val (results, result);

                  g_string_free (locations, TRUE);
                }
              cleanup_iterator (&prognosis);
            }
          report_add_results_array (report, results);
          g_array_free (results, TRUE);

          if (prognosis_report_host)
            {
              gchar *hostname, *best;

              /* Complete the report_host. */

              report_host_set_end_time (prognosis_report_host, time (NULL));

              hostname = report_host_hostname (report_host);
              if (hostname) {
                insert_report_host_detail (report, ip, "cve", "",
                                           "CVE Scanner", "hostname", hostname,
                                           NULL);
                g_free(hostname);
              }

              best = report_host_best_os_cpe (report_host);
              if (best) {
                insert_report_host_detail (report, ip, "cve", "",
                                           "CVE Scanner", "best_os_cpe", best,
                                           NULL);
                g_free(best);
              }

              best = report_host_best_os_txt (report_host);
              if (best) {
                insert_report_host_detail (report, ip, "cve", "",
                                           "CVE Scanner", "best_os_txt", best,
                                           NULL);
                g_free(best);
              }

              insert_report_host_detail (report, ip, "cve", "",
                                         "CVE Scanner", "CVE Scan", "1", NULL);
              update_report_modification_time (report);
            }
        }
      cleanup_iterator (&report_hosts);
    }

  g_free (ip);
  return 0;
}
