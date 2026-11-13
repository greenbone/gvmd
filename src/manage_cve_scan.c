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

#include <assert.h>
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
    gvmd_config_get_int (kf, "cve_scan", "cve_scan_matching_version",
                         &has_matching_version, &config_matching_version);

  gvmd_config_resolve_int (CVE_SCAN_MATCHING_VERSION_ENV, has_matching_version,
                           config_matching_version, &matching_version);

  if (matching_version != 0 && matching_version != 1)
    {
      g_warning ("Invalid CVE scan matching version %d; using default "
                 "version %d",
                 matching_version, DEFAULT_CVE_SCAN_MATCHING_VERSION);

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

/* Loaded configurations and inventories own their parsed CPEs. Evaluation
 * borrows these immutable objects and performs no storage access. */
typedef enum
{
  CPE_OPERATOR_AND,
  CPE_OPERATOR_OR
} cpe_operator_t;

typedef struct
{
  cpe_struct_t cpe;
  char *product;
  char *version_start_incl, *version_start_excl;
  char *version_end_incl, *version_end_excl;
  gboolean vulnerable;
  gboolean unavailable; /* Match-string feed has not supplied this criterion. */
} cpe_criterion_t;

typedef struct
{
  resource_t id;
  cpe_operator_t operator;
  gboolean negate;
  GPtrArray *criteria;
  GPtrArray *children; /* Borrowed nodes; configurations own all nodes. */
} cpe_node_t;

typedef struct
{
  cpe_node_t *root;
  GPtrArray *nodes;
} cpe_configuration_t;

typedef struct
{
  char *uri;
  cpe_struct_t cpe;
} cpe_host_product_t;

typedef struct
{
  gboolean match;
  gboolean vulnerable;
} cpe_evaluation_t;

/**
 * @brief Free a loaded CPE criterion.
 *
 * @param[in] data  Criterion to free.
 */
static void
free_cpe_criterion (gpointer data)
{
  cpe_criterion_t *criterion = data;
  cpe_struct_free (&criterion->cpe);
  g_free (criterion->product);
  g_free (criterion->version_start_incl);
  g_free (criterion->version_start_excl);
  g_free (criterion->version_end_incl);
  g_free (criterion->version_end_excl);
  g_free (criterion);
}

/**
 * @brief Free a loaded node and its criteria.
 *
 * @param[in] data  Node to free; child nodes are borrowed.
 */
static void
free_cpe_node (gpointer data)
{
  cpe_node_t *node = data;
  g_ptr_array_free (node->criteria, TRUE);
  g_ptr_array_free (node->children, TRUE);
  g_free (node);
}

/**
 * @brief Free a configuration and all its nodes.
 *
 * @param[in] data  Configuration to free, or NULL.
 */
static void
free_cpe_configuration (gpointer data)
{
  cpe_configuration_t *configuration = data;
  if (configuration == NULL)
    return;
  g_ptr_array_free (configuration->nodes, TRUE);
  g_free (configuration);
}

/**
 * @brief Allocate an empty configuration node.
 *
 * @param[in] id        Node ID.
 * @param[in] operator  Operator combining the node operands.
 * @param[in] negate    Whether to negate the completed node result.
 *
 * @return Newly allocated node.
 */
static cpe_node_t *
new_cpe_node (resource_t id, cpe_operator_t operator, gboolean negate)
{
  cpe_node_t *node = g_new0 (cpe_node_t, 1);
  node->id = id;
  node->operator= operator;
  node->negate = negate;
  node->criteria = g_ptr_array_new_with_free_func (free_cpe_criterion);
  node->children = g_ptr_array_new ();
  return node;
}

/**
 * @brief Load all nodes and criteria of one NVD 2.0 configuration.
 *
 * Nodes are ordered so repeated criterion rows can be attached to their node.
 * Empty nodes survive the outer joins. Unavailable match strings remain false
 * operands; reject them under negation to avoid inventing positive matches.
 *
 * @param[in] root_id  Configuration root node ID.
 *
 * @return Newly allocated configuration, or NULL if it cannot be loaded.
 */
static cpe_configuration_t *
load_cpe_configuration (resource_t root_id)
{
  iterator_t rows;
  cpe_configuration_t *configuration = g_new0 (cpe_configuration_t, 1);
  cpe_node_t *node = NULL;
  gboolean valid = TRUE;

  configuration->nodes = g_ptr_array_new_with_free_func (free_cpe_node);
  init_iterator (
    &rows,
    "SELECT n.id, n.operator, n.negate, c.id, c.vulnerable, r.criteria,"
    " r.version_start_incl, r.version_start_excl,"
    " r.version_end_incl, r.version_end_excl"
    " FROM scap.cpe_match_nodes n"
    " LEFT JOIN scap.cpe_nodes_match_criteria c ON c.node_id = n.id"
    " LEFT JOIN scap.cpe_match_strings r"
    " ON r.match_criteria_id = c.match_criteria_id"
    " WHERE n.root_id = %llu OR n.id = %llu ORDER BY n.id, c.id;",
    root_id, root_id);
  while (next (&rows))
    {
      resource_t id = iterator_int64 (&rows, 0);
      if (node == NULL || node->id != id)
        {
          const char *operator= iterator_string (&rows, 1);
          if (operator== NULL || (strcmp (operator, "AND")
                                  && strcmp (operator, "OR")))
            {
              valid = FALSE;
              break;
            }
          node = new_cpe_node (id,
                               strcmp (operator, "AND") == 0 ? CPE_OPERATOR_AND
                                                             : CPE_OPERATOR_OR,
                               iterator_int (&rows, 2) != 0);
          g_ptr_array_add (configuration->nodes, node);
          if (id == root_id)
            configuration->root = node;
        }
      if (!iterator_null (&rows, 3))
        {
          const char *criteria = iterator_string (&rows, 5);
          cpe_criterion_t *criterion;
          criterion = g_new0 (cpe_criterion_t, 1);
          cpe_struct_init (&criterion->cpe);
          criterion->unavailable = criteria == NULL;
          if (criteria)
            {
              uri_cpe_to_cpe_struct (criteria, &criterion->cpe);
              criterion->product = uri_cpe_to_uri_product (criteria);
            }
          criterion->vulnerable = iterator_int (&rows, 4) != 0;
          criterion->version_start_incl = g_strdup (iterator_string (&rows, 6));
          criterion->version_start_excl = g_strdup (iterator_string (&rows, 7));
          criterion->version_end_incl = g_strdup (iterator_string (&rows, 8));
          criterion->version_end_excl = g_strdup (iterator_string (&rows, 9));
          g_ptr_array_add (node->criteria, criterion);
        }
    }
  cleanup_iterator (&rows);
  if (!valid || configuration->root == NULL)
    {
      g_warning ("%s: Invalid CPE configuration %llu", __func__, root_id);
      free_cpe_configuration (configuration);
      return NULL;
    }
  for (guint i = 0; i < configuration->nodes->len; i++)
    {
      node = g_ptr_array_index (configuration->nodes, i);
      for (guint j = 0; j < node->criteria->len; j++)
        {
          const cpe_criterion_t *criterion =
            g_ptr_array_index (node->criteria, j);
          if (criterion->unavailable
              && (node->negate || configuration->root->negate))
            {
              g_warning ("%s: Unavailable criterion under negation in %llu",
                         __func__, root_id);
              free_cpe_configuration (configuration);
              return NULL;
            }
        }
      if (node != configuration->root)
        g_ptr_array_add (configuration->root->children, node);
    }
  return configuration;
}

/**
 * @brief Cache successful and failed loads for the duration of a host scan.
 *
 * @param[in,out] cache  Host scan cache owning configuration values and ID
 * keys.
 * @param[in] root_id    Configuration root node ID.
 *
 * @return Borrowed cached configuration, or NULL for a failed load.
 */
static cpe_configuration_t *
get_cpe_configuration (GHashTable *cache, resource_t root_id)
{
  gpointer value;
  resource_t *key;
  cpe_configuration_t *configuration;

  if (g_hash_table_lookup_extended (cache, &root_id, NULL, &value))
    return value;
  configuration = load_cpe_configuration (root_id);
  key = g_new (resource_t, 1);
  *key = root_id;
  g_hash_table_insert (cache, key, configuration);
  return configuration;
}

/**
 * @brief Free a parsed host CPE.
 *
 * @param[in] data  Host product to free.
 */
static void
free_cpe_host_product (gpointer data)
{
  cpe_host_product_t *product = data;
  cpe_struct_free (&product->cpe);
  g_free (product->uri);
  g_free (product);
}

/**
 * @brief Allocate and parse a host CPE.
 *
 * @param[in] uri  CPE URI to copy and parse.
 *
 * @return Newly allocated host product.
 */
static cpe_host_product_t *
new_cpe_host_product (const char *uri)
{
  cpe_host_product_t *product = g_new0 (cpe_host_product_t, 1);
  product->uri = g_strdup (uri);
  cpe_struct_init (&product->cpe);
  uri_cpe_to_cpe_struct (uri, &product->cpe);
  return product;
}

/**
 * @brief Read and parse the report host's App CPEs once.
 *
 * @param[in] report_host  Report host supplying the inventory.
 *
 * @return Newly allocated array owning its parsed host products.
 */
static GPtrArray *
load_cpe_host_inventory (report_host_t report_host)
{
  iterator_t rows;
  GPtrArray *inventory = g_ptr_array_new_with_free_func (free_cpe_host_product);
  init_host_details_cpe_iterator (&rows, report_host);
  while (next (&rows))
    g_ptr_array_add (
      inventory, new_cpe_host_product (host_details_cpe_iterator_cpe (&rows)));
  cleanup_iterator (&rows);
  return inventory;
}

/**
 * @brief Check a parsed CPE against a criterion and its version bounds.
 *
 * @param[in] criterion  Criterion to evaluate.
 * @param[in] target     Parsed CPE being checked.
 *
 * @return TRUE if the CPE and version satisfy the criterion.
 */
static gboolean
cpe_criterion_matches (const cpe_criterion_t *criterion,
                       const cpe_struct_t *target)
{
  /* The library matcher does not modify either CPE, but its API lacks const. */
  cpe_struct_t source = criterion->cpe;
  cpe_struct_t candidate = *target;

  return cpe_struct_match (&source, &candidate)
         && check_version (target->version, criterion->version_start_incl,
                           criterion->version_start_excl,
                           criterion->version_end_incl,
                           criterion->version_end_excl)
              == 1;
}

/**
 * @brief Combine independent operand results, retaining vulnerable evidence.
 *
 * @param[in,out] result  Accumulated evaluation.
 * @param[in] operand     Independent operand evaluation.
 * @param[in] is_and      TRUE for conjunction, FALSE for disjunction.
 */
static void
combine_cpe_evaluation (cpe_evaluation_t *result, cpe_evaluation_t operand,
                        gboolean is_and)
{
  result->match =
    is_and ? result->match && operand.match : result->match || operand.match;
  result->vulnerable |= operand.match && operand.vulnerable;
}

/**
 * @brief Evaluate an immutable node without storage access.
 *
 * @param[in] node       Node to evaluate.
 * @param[in] inventory  Parsed host product inventory.
 * @param[in] host_cpe   CPE for which vulnerable evidence is required.
 *
 * @return Node applicability and vulnerable-product evidence.
 */
static cpe_evaluation_t
evaluate_cpe_node (const cpe_node_t *node, const GPtrArray *inventory,
                   const cpe_struct_t *host_cpe)
{
  gboolean is_and = node->operator== CPE_OPERATOR_AND;
  cpe_evaluation_t result = {is_and, FALSE};

  if (node->children->len == 0 && node->criteria->len == 0)
    {
      result.match = FALSE;
      goto complete;
    }

  for (guint i = 0; i < node->children->len; i++)
    {
      cpe_evaluation_t child = evaluate_cpe_node (
        g_ptr_array_index (node->children, i), inventory, host_cpe);
      combine_cpe_evaluation (&result, child, is_and);
      if ((is_and && !result.match)
          || (!is_and && result.match && result.vulnerable))
        goto complete;
    }
  for (guint i = 0; i < node->criteria->len; i++)
    {
      const cpe_criterion_t *criterion = g_ptr_array_index (node->criteria, i);
      cpe_evaluation_t operand = {FALSE, FALSE};
      for (guint j = 0; !criterion->unavailable && j < inventory->len; j++)
        {
          const cpe_host_product_t *product = g_ptr_array_index (inventory, j);
          if (g_str_has_prefix (product->uri, criterion->product)
              && cpe_criterion_matches (criterion, &product->cpe))
            {
              operand.match = TRUE;
              break;
            }
        }
      operand.vulnerable = operand.match && criterion->vulnerable
                           && cpe_criterion_matches (criterion, host_cpe);
      combine_cpe_evaluation (&result, operand, is_and);
      if ((is_and && !result.match)
          || (!is_and && result.match && result.vulnerable))
        goto complete;
    }
complete:
  result.vulnerable &= result.match;
  if (node->negate)
    {
      result.match = !result.match;
      result.vulnerable = FALSE;
    }
  return result;
}

/**
 * @brief Evaluate a loaded configuration against a host inventory.
 *
 * @param[in] configuration  Configuration to evaluate.
 * @param[in] inventory      Parsed host product inventory.
 * @param[in] host_cpe       CPE for which vulnerable evidence is required.
 *
 * @return Configuration applicability and vulnerable-product evidence.
 */
static cpe_evaluation_t
evaluate_cpe_configuration (const cpe_configuration_t *configuration,
                            const GPtrArray *inventory,
                            const cpe_struct_t *host_cpe)
{
  return evaluate_cpe_node (configuration->root, inventory, host_cpe);
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
cve_scan_report_host_json (task_t task, report_t report,
                           report_host_t report_host, gchar *ip, int start_time,
                           int *prognosis_report_host, GArray *results)
{
  GPtrArray *inventory = load_cpe_host_inventory (report_host);
  GHashTable *configurations = g_hash_table_new_full (
    g_int64_hash, g_int64_equal, g_free, free_cpe_configuration);
  for (guint host_index = 0; host_index < inventory->len; host_index++)
    {
      iterator_t cpe_match_root_node;
      iterator_t locations_iter;
      result_t result;
      char *cpe_product;
      const char *host_cpe;
      double severity;

      const cpe_host_product_t *product =
        g_ptr_array_index (inventory, host_index);
      host_cpe = product->uri;
      cpe_product = uri_cpe_to_uri_product (host_cpe);
      init_cpe_match_nodes_iterator (&cpe_match_root_node, cpe_product);
      while (next (&cpe_match_root_node))
        {
          result_t root_node;
          cpe_evaluation_t evaluation;
          cpe_configuration_t *configuration;

          root_node = cpe_match_nodes_iterator_root_id (&cpe_match_root_node);
          configuration = get_cpe_configuration (configurations, root_node);
          if (configuration == NULL)
            continue;
          evaluation = evaluate_cpe_configuration (configuration, inventory,
                                                   &product->cpe);
          if (evaluation.match && evaluation.vulnerable)
            {
              GString *locations;
              gchar *desc, *description, *cve;
              const char *app;

              if (*prognosis_report_host == 0)
                *prognosis_report_host =
                  manage_report_host_add (report, ip, start_time, 0);

              severity = sql_double (
                "SELECT severity FROM scap.cves, scap.cpe_match_nodes"
                " WHERE scap.cves.id = scap.cpe_match_nodes.cve_id"
                " AND scap.cpe_match_nodes.id = %llu;",
                root_node);

              app = host_cpe;
              cve =
                sql_string ("SELECT name FROM scap.cves, scap.cpe_match_nodes"
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

                  insert_report_host_detail (
                    report, ip, "cve", cve, "CVE Scanner", app, location, NULL);

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

              desc = g_strdup_printf (
                "The host carries the product: %s\n"
                "It is vulnerable according to: %s.\n"
                "%s%s%s"
                "\n"
                "%s",
                app, cve, locations->len ? "The product was found at: " : "",
                locations->len ? locations->str : "",
                locations->len ? ".\n" : "", description);

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
  g_hash_table_destroy (configurations);
  g_ptr_array_free (inventory, TRUE);
}

/**
 * @brief Add CVE results using version 0 matching.
 *
 * Version 0 matches detected CPEs against CVE affected-product lists.
 */
static void
cve_scan_report_host_v0 (task_t task, report_t report,
                         report_host_t report_host, const char *ip,
                         int start_time, int *prognosis_report_host,
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

      insert_report_host_detail (report, ip, "cve", cve, "CVE Scanner", "App",
                                 app, NULL);

      init_app_locations_iterator (&locations_iter, report_host, app);

      while (next (&locations_iter))
        {
          const char *location;

          location = app_locations_iterator_location (&locations_iter);

          if (location == NULL)
            {
              g_warning ("%s: Location is null for ip %s, app %s", __func__, ip,
                         app);
              continue;
            }

          if (locations->len)
            g_string_append (locations, ", ");

          g_string_append (locations, location);

          insert_report_host_detail (report, ip, "cve", cve, "CVE Scanner", app,
                                     location, NULL);

          insert_report_host_detail (report, ip, "cve", cve, "CVE Scanner",
                                     "detected_at", location, NULL);

          insert_report_host_detail (report, ip, "cve", cve, "CVE Scanner",
                                     "detected_by", cve, NULL);
        }

      cleanup_iterator (&locations_iter);

      desc = g_strdup_printf (
        "The host carries the product: %s\n"
        "It is vulnerable according to: %s.\n"
        "%s%s%s"
        "\n"
        "%s",
        app, cve, locations->len ? "The product was found at: " : "",
        locations->len ? locations->str : "", locations->len ? ".\n" : "",
        prognosis_iterator_description (&prognosis));

      g_debug ("%s: making result with severity %1.1f desc [%s]", __func__,
               severity, desc);

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
cve_scan_report_host_v1 (task_t task, report_t report,
                         report_host_t report_host, gchar *ip, int start_time,
                         int *prognosis_report_host, GArray *results)
{
  cve_scan_report_host_json (task, report, report_host, ip, start_time,
                             prognosis_report_host, results);
}

/**
 * @brief Check whether the SCAP data required by version 1 is available.
 *
 * @return TRUE if version 1 is supported, FALSE otherwise.
 */
static gboolean
cve_scan_v1_supported (void)
{
  return sql_int64_0 ("SELECT count(1)"
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
cve_scan_report_host (task_t task, report_t report, report_host_t report_host,
                      gchar *ip, int start_time, int *prognosis_report_host,
                      GArray *results)
{
  int matching_version;

  matching_version = cve_scan_matching_version ();

  g_debug ("%s: CVE scan matching version %d", __func__, matching_version);

  if (matching_version == 1)
    {
      if (cve_scan_v1_supported ())
        {
          cve_scan_report_host_v1 (task, report, report_host, ip, start_time,
                                   prognosis_report_host, results);
          return;
        }

      g_warning ("%s: CVE scan matching version 1 is configured, but the "
                 "required SCAP data is unavailable; using version 0",
                 __func__);
    }

  cve_scan_report_host_v0 (task, report, report_host, ip, start_time,
                           prognosis_report_host, results);
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

          cve_scan_report_host (task, report, report_host, ip, start_time,
                                &prognosis_report_host, results);

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
                                             "CVE Scanner", "best_os_cpe", best,
                                             NULL);
                  g_free (best);
                }

              best = report_host_best_os_txt (report_host);
              if (best)
                {
                  insert_report_host_detail (report, ip, "cve", "",
                                             "CVE Scanner", "best_os_txt", best,
                                             NULL);
                  g_free (best);
                }

              insert_report_host_detail (report, ip, "cve", "", "CVE Scanner",
                                         "CVE Scan", "1", NULL);
              update_report_modification_time (report);
            }
        }

      cleanup_iterator (&report_hosts);
    }

  g_free (ip);
  return 0;
}
