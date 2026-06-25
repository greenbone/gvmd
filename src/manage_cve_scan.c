/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager CVE scan handling.
 */

#include "manage_cve_scan.h"

#include "gvmd_config.h"
#include "manage_sql.h"
#include "manage_sql_assets.h"

#include <util/cpeutils.h>
#include <util/versionutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Default CVE scan matching version.
 */
#define DEFAULT_CVE_SCAN_MATCHING_VERSION 0

/**
 * @brief Environment variable for CVE scan matching version.
 */
#define CVE_SCAN_MATCHING_VERSION_ENV "GVMD_CVE_SCAN_MATCHING_VERSION"

/**
 * @brief Get the configured CVE scan matching version.
 *
 * Resolution order:
 *  - Environment variable.
 *  - Configuration file.
 *  - Default version 0.
 *
 * @return Matching version 0 or 1.
 */
int
cve_scan_matching_version (void)
{
  GKeyFile *kf;
  gboolean has_matching_version;
  int config_matching_version;
  int matching_version;

  has_matching_version = FALSE;
  config_matching_version = DEFAULT_CVE_SCAN_MATCHING_VERSION;
  matching_version = DEFAULT_CVE_SCAN_MATCHING_VERSION;

  kf = get_gvmd_config ();
  if (kf)
    gvmd_config_get_int (kf,
                         "cve_scan",
                         "cve_scan_matching_version",
                         &has_matching_version,
                         &config_matching_version);

  gvmd_config_resolve_int (CVE_SCAN_MATCHING_VERSION_ENV,
                           has_matching_version,
                           config_matching_version,
                           &matching_version);

  if (matching_version != 0 && matching_version != 1)
    {
      g_warning ("Invalid CVE scan matching version %d; using default "
                 "version %d",
                 matching_version,
                 DEFAULT_CVE_SCAN_MATCHING_VERSION);

      return DEFAULT_CVE_SCAN_MATCHING_VERSION;
    }

  return matching_version;
}

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
check_version (const gchar *target, const gchar *start_incl,
               const gchar *start_excl, const gchar *end_incl,
               const gchar *end_excl)
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
check_cpe_match_rule (long long int node, gboolean *match, gboolean *vulnerable,
                      report_host_t report_host, const char *host_cpe)
{
  iterator_t cpe_match_node_childs;
  gchar *operator;
  iterator_t cpe_match_ranges;

  operator = sql_string (
    "SELECT operator FROM scap.cpe_match_nodes WHERE id = %llu", node);
  if (operator == NULL)
    return;
  init_cpe_match_node_childs_iterator (&cpe_match_node_childs, node);
  while (next (&cpe_match_node_childs))
    {
      long long int child_node;
      child_node = cpe_match_node_childs_iterator_id (&cpe_match_node_childs);
      check_cpe_match_rule (child_node, match, vulnerable, report_host,
                            host_cpe);
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

              severity = sql_double (
                "SELECT severity FROM scap.cves, scap.cpe_match_nodes"
                " WHERE scap.cves.id = scap.cpe_match_nodes.cve_id"
                " AND scap.cpe_match_nodes.id = %llu;",
                root_node);

              app = host_cpe;
              cve = sql_string (
                "SELECT name FROM scap.cves, scap.cpe_match_nodes"
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
                                             "CVE Scanner", app, location,
                                             NULL);

                  insert_report_host_detail (report, ip, "cve", cve,
                                             "CVE Scanner", "detected_at",
                                             location, NULL);

                  insert_report_host_detail (report, ip, "cve", cve,
                                             "CVE Scanner", "detected_by",
                                             /* Detected by itself. */
                                             cve, NULL);
                }
              cleanup_iterator (&locations_iter);

              description = sql_string (
                "SELECT description FROM scap.cves, scap.cpe_match_nodes"
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
 * @brief Add CVE results using version 0 matching.
 *
 * Version 0 matches detected CPEs against CVE affected-product lists.
 */
static void
cve_scan_report_host_v0 (task_t task,
                         report_t report,
                         report_host_t report_host,
                         const char *ip,
                         int start_time,
                         int *prognosis_report_host,
                         GArray *results)
{
  iterator_t prognosis;

  init_host_prognosis_iterator (&prognosis, report_host);

  while (next (&prognosis))
    {
      const char *app, *cve;
      double severity;
      gchar *desc;
      iterator_t locations_iter;
      GString *locations;
      result_t result;

      if (*prognosis_report_host == 0)
        *prognosis_report_host =
          manage_report_host_add (report, ip, start_time, 0);

      severity = prognosis_iterator_cvss_double (&prognosis);
      app = prognosis_iterator_cpe (&prognosis);
      cve = prognosis_iterator_cve (&prognosis);
      locations = g_string_new ("");

      insert_report_host_detail (report, ip, "cve", cve,
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
      g_array_append_val (results, result);

      g_free (desc);
      g_string_free (locations, TRUE);
    }

  cleanup_iterator (&prognosis);
}

/**
 * @brief Add CVE results using version 1 matching.
 *
 * Version 1 evaluates the CVE match criteria from the JSON SCAP data.
 */
static void
cve_scan_report_host_v1 (task_t task,
                         report_t report,
                         report_host_t report_host,
                         gchar *ip,
                         int start_time,
                         int *prognosis_report_host,
                         GArray *results)
{
  cve_scan_report_host_json (task,
                             report,
                             report_host,
                             ip,
                             start_time,
                             prognosis_report_host,
                             results);
}

/**
 * @brief Check whether the SCAP data required by version 1 is available.
 *
 * @return TRUE if version 1 is supported, FALSE otherwise.
 */
static gboolean
cve_scan_v1_supported (void)
{
  return sql_int64_0 (
           "SELECT count(1)"
           " FROM information_schema.tables"
           " WHERE table_schema = 'scap'"
           " AND table_name = 'cpe_match_nodes';")
         > 0;
}

/**
 * @brief Run the configured CVE matching implementation.
 *
 * Falls back to version 0 when version 1 is configured but unavailable.
 */
static void
cve_scan_report_host (task_t task,
                      report_t report,
                      report_host_t report_host,
                      gchar *ip,
                      int start_time,
                      int *prognosis_report_host,
                      GArray *results)
{
  int matching_version;

  matching_version = cve_scan_matching_version ();

  g_debug ("%s: CVE scan matching version %d", __func__, matching_version);

  if (matching_version == 1)
    {
      if (cve_scan_v1_supported ())
        {
          cve_scan_report_host_v1 (task,
                                   report,
                                   report_host,
                                   ip,
                                   start_time,
                                   prognosis_report_host,
                                   results);
          return;
        }

      g_warning ("%s: CVE scan matching version 1 is configured, but the "
                 "required SCAP data is unavailable; using version 0",
                 __func__);
    }

  cve_scan_report_host_v0 (task,
                           report,
                           report_host,
                           ip,
                           start_time,
                           prognosis_report_host,
                           results);
}

/**
 * @brief Perform a CVE "scan" on a host.
 *
 * The matching version is selected from the gvmd configuration.
 *
 * @param[in] task      Task.
 * @param[in] report    Report to add the host, results and details to.
 * @param[in] gvm_host  Host.
 *
 * @return 0 on success, 1 if getting the previous report host failed.
 */
int
cve_scan_host (task_t task, report_t report, gvm_host_t *gvm_host)
{
  report_host_t report_host;
  gchar *host, *ip;

  assert (task);
  assert (report);
  assert (gvm_host);

  host = gvm_host_value_str (gvm_host);

  ip = report_host_ip (host);
  if (ip == NULL)
    ip = g_strdup (host);

  g_free (host);

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

      init_report_host_iterator (&report_hosts, 0, NULL, report_host);

      if (next (&report_hosts))
        {
          int prognosis_report_host, start_time;
          GArray *results;

          results = g_array_new (TRUE, TRUE, sizeof (result_t));
          start_time = time (NULL);
          prognosis_report_host = 0;

          cve_scan_report_host (task,
                                report,
                                report_host,
                                ip,
                                start_time,
                                &prognosis_report_host,
                                results);

          report_add_results_array (report, results);
          g_array_free (results, TRUE);

          if (prognosis_report_host)
            {
              gchar *hostname, *best;

              /* Complete the report_host. */

              report_host_set_end_time (prognosis_report_host, time (NULL));

              hostname = report_host_hostname (report_host);
              if (hostname)
                {
                  insert_report_host_detail (report, ip, "cve", "",
                                             "CVE Scanner", "hostname",
                                             hostname, NULL);
                  g_free (hostname);
                }

              best = report_host_best_os_cpe (report_host);
              if (best)
                {
                  insert_report_host_detail (report, ip, "cve", "",
                                             "CVE Scanner", "best_os_cpe",
                                             best, NULL);
                  g_free (best);
                }

              best = report_host_best_os_txt (report_host);
              if (best)
                {
                  insert_report_host_detail (report, ip, "cve", "",
                                             "CVE Scanner", "best_os_txt",
                                             best, NULL);
                  g_free (best);
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
