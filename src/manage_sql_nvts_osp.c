/* Copyright (C) 2010-2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: OSP NVT SQL logic
 *
 * NVT SQL logic specific to OSP in the GVM management layer.
 */

#include "manage_sql_nvts_osp.h"

#include "manage.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "sql.h"

#include <gvm/base/cvss.h>
#include <gvm/osp/osp.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_ref_insert_size = VT_REF_INSERT_SIZE_DEFAULT;

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_sev_insert_size = VT_SEV_INSERT_SIZE_DEFAULT;

/**
 * @brief Update NVT from VT XML.
 *
 * @param[in]  vt           OSP GET_VTS VT element.
 * @param[in]  oid          OID of NVT.
 * @param[in]  preferences  All NVT preferences.
 *
 * @return 0 success, -1 error.
 */
static int
update_preferences_from_vt (element_t vt, const gchar *oid, GList **preferences)
{
  element_t params, param;

  assert (preferences);

  params = element_child (vt, "params");
  if (params == NULL)
    return 0;

  param = element_first_child (params);
  while (param)
    {
      if (strcasecmp (element_name (param), "param") == 0)
        {
          gchar *type, *id;
          element_t name, def;

          type = element_attribute (param, "type");
          id = element_attribute (param, "id");
          name = element_child (param, "name");
          def = element_child (param, "default");

          if (type == NULL)
            {
              GString *debug = g_string_new ("");
              g_warning ("%s: PARAM missing type attribute", __func__);
              print_element_to_string (param, debug);
              g_warning ("%s: PARAM: %s", __func__, debug->str);
              g_string_free (debug, TRUE);
            }
          else if (id == NULL)
            {
              GString *debug = g_string_new ("");
              g_warning ("%s: PARAM missing id attribute", __func__);
              print_element_to_string (param, debug);
              g_warning ("%s: PARAM: %s", __func__, debug->str);
              g_string_free (debug, TRUE);
            }
          else if (name == NULL)
            {
              GString *debug = g_string_new ("");
              g_warning ("%s: PARAM missing NAME", __func__);
              print_element_to_string (param, debug);
              g_warning ("%s: PARAM: %s", __func__, debug->str);
              g_string_free (debug, TRUE);
            }
          else
            {
              gchar *full_name, *text;
              preference_t *preference;

              text = element_text (name);
              full_name = g_strdup_printf ("%s:%s:%s:%s",
                                           oid,
                                           id,
                                           type,
                                           text);

              blank_control_chars (full_name);
              preference = g_malloc0 (sizeof (preference_t));
              preference->free_strings = 1;
              preference->name = full_name;
              if (def)
                preference->value = element_text (def);
              else
                preference->value = g_strdup ("");
              preference->nvt_oid = g_strdup (oid);
              preference->id = g_strdup (id);
              preference->type = g_strdup (type);
              preference->pref_name = text;
              *preferences = g_list_prepend (*preferences, preference);
            }

          g_free (type);
          g_free (id);
        }

      param = element_next (param);
    }

  return 0;
}

/**
 * @brief Create NVTI structure from VT XML.
 *
 * @param[in]  vt           OSP GET_VTS VT element.
 *
 * @return The NVTI object on success (needs to be free'd), NULL on error.
 */
static nvti_t *
nvti_from_vt (element_t vt)
{
  nvti_t *nvti = nvti_new ();
  gchar *id, *category_text;
  element_t name, summary, insight, affected, impact, detection, solution;
  element_t creation_time, modification_time;
  element_t refs, ref, custom, family, category, deprecated;
  element_t severities, severity;

  id = element_attribute (vt, "id");
  if (id == NULL)
    {
      g_warning ("%s: VT missing id attribute", __func__);
      nvti_free (nvti);
      return NULL;
    }

  nvti_set_oid (nvti, id);
  g_free (id);

  name = element_child (vt, "name");
  if (name == NULL)
    {
      g_warning ("%s: VT missing NAME", __func__);
      nvti_free (nvti);
      return NULL;
    }
  nvti_put_name (nvti, element_text (name));

  summary = element_child (vt, "summary");
  if (summary)
    nvti_put_summary (nvti, element_text (summary));

  insight = element_child (vt, "insight");
  if (insight)
    nvti_put_insight (nvti, element_text (insight));

  affected = element_child (vt, "affected");
  if (affected)
    nvti_put_affected (nvti, element_text (affected));

  impact = element_child (vt, "impact");
  if (impact)
    nvti_put_impact (nvti, element_text (impact));

  creation_time = element_child (vt, "creation_time");
  if (creation_time) {
    gchar *text;

    text = element_text (creation_time);
    nvti_set_creation_time (nvti, strtol (text, NULL, 10));
    g_free (text);
  }

  modification_time = element_child (vt, "modification_time");
  if (modification_time) {
    gchar *text;

    text = element_text (modification_time);
    nvti_set_modification_time (nvti, strtol(text, NULL, 10));
    g_free (text);
  }

  detection = element_child (vt, "detection");
  if (detection)
    {
      gchar *qod;

      nvti_put_detection (nvti, element_text (detection));

      qod = element_attribute (detection, "qod");
      if (qod == NULL) {
        gchar *qod_type;

        qod_type = element_attribute (detection, "qod_type");
        nvti_set_qod_type (nvti, qod_type);
        g_free (qod_type);
      }
      else
        nvti_set_qod (nvti, qod);
      g_free (qod);
    }

  solution = element_child (vt, "solution");
  if (solution)
    {
      gchar *type, *method;

      nvti_put_solution (nvti, element_text (solution));

      type = element_attribute (solution, "type");
      if (type == NULL)
        g_debug ("%s: SOLUTION missing type", __func__);
      else
        nvti_set_solution_type (nvti, type);
      g_free (type);

      method = element_attribute (solution, "method");
      if (method)
        nvti_set_solution_method (nvti, method);
      g_free (method);
    }

  severities = element_child (vt, "severities");
  if (severities == NULL)
    {
      g_warning ("%s: VT missing SEVERITIES", __func__);
      nvti_free (nvti);
      return NULL;
    }

  severity = element_first_child (severities);
  while (severity)
    {
      gchar *severity_type;

      severity_type = element_attribute (severity, "type");

      if (severity_type == NULL)
        {
          GString *debug = g_string_new ("");
          g_warning ("%s: SEVERITY missing type attribute", __func__);
          print_element_to_string (severity, debug);
          g_warning ("%s: severity: %s", __func__, debug->str);
          g_string_free (debug, TRUE);
        }
      else
        {
          element_t value;

          value = element_child (severity, "value");

          if (!value)
            {
              GString *debug = g_string_new ("");
              g_warning ("%s: SEVERITY missing value element", __func__);
              print_element_to_string (severity, debug);
              g_warning ("%s: severity: %s", __func__, debug->str);
              g_string_free (debug, TRUE);
            }
          else
            {
              element_t origin, severity_date;
              double cvss_base_dbl;
              gchar *cvss_base, *value_text, *origin_text;
              time_t parsed_severity_date;

              value_text = element_text (value);

              cvss_base_dbl
                = get_cvss_score_from_base_metrics (value_text);

              origin
                = element_child (severity, "origin");
              severity_date
                = element_child (severity, "date");

              if (severity_date) {
                gchar *text;

                text = element_text (severity_date);
                parsed_severity_date = strtol (text, NULL, 10);
                g_free (text);
              }
              else
                parsed_severity_date = nvti_creation_time (nvti);

              origin_text = origin ? element_text (origin) : NULL,
              nvti_add_vtseverity (nvti,
                vtseverity_new (severity_type,
                                origin_text,
                                parsed_severity_date,
                                cvss_base_dbl,
                                value_text));
              g_free (origin_text);

              nvti_add_tag (nvti, "cvss_base_vector", value_text);

              cvss_base = g_strdup_printf ("%.1f",
                get_cvss_score_from_base_metrics (value_text));
              nvti_set_cvss_base (nvti, cvss_base);
              g_free (cvss_base);
              g_free (value_text);
            }

          g_free (severity_type);
        }

      severity = element_next (severity);
    }

  refs = element_child (vt, "refs");
  if (refs)
    {
      ref = element_first_child (refs);
      while (ref)
        {
          gchar *ref_type;

          ref_type = element_attribute (ref, "type");
          if (ref_type == NULL)
            {
              GString *debug = g_string_new ("");
              g_warning ("%s: REF missing type attribute", __func__);
              print_element_to_string (ref, debug);
              g_warning ("%s: ref: %s", __func__, debug->str);
              g_string_free (debug, TRUE);
            }
          else
            {
              gchar *ref_id;

              ref_id = element_attribute (ref, "id");
              if (ref_id == NULL)
                {
                  GString *debug = g_string_new ("");
                  g_warning ("%s: REF missing id attribute", __func__);
                  print_element_to_string (ref, debug);
                  g_warning ("%s: ref: %s", __func__, debug->str);
                  g_string_free (debug, TRUE);
                }
              else
                {
                  nvti_add_vtref (nvti, vtref_new (ref_type, ref_id, NULL));
                  g_free (ref_id);
                }

              g_free (ref_type);
            }

          ref = element_next (ref);
        }
    }

  custom = element_child (vt, "custom");
  if (custom == NULL)
    {
      g_warning ("%s: VT missing CUSTOM", __func__);
      nvti_free (nvti);
      return NULL;
    }

  family = element_child (custom, "family");
  if (family == NULL)
    {
      g_warning ("%s: VT/CUSTOM missing FAMILY", __func__);
      nvti_free (nvti);
      return NULL;
    }
  nvti_put_family (nvti, element_text (family));

  category = element_child (custom, "category");
  if (category == NULL)
    {
      g_warning ("%s: VT/CUSTOM missing CATEGORY", __func__);
      nvti_free (nvti);
      return NULL;
    }
  category_text = element_text (category);
  nvti_set_category (nvti, atoi (category_text));
  g_free (category_text);

  deprecated = element_child (custom, "deprecated");
  if (deprecated)
    {
      gchar *text;

      text = element_text (deprecated);
      nvti_add_tag (nvti, "deprecated", text);
      g_free (text);
    }

  return nvti;
}

/**
 * @brief Update NVTs from VTs XML.
 *
 * @param[in]  get_vts_response      OSP GET_VTS response.
 * @param[in]  scanner_feed_version  Version of feed from scanner.
 * @param[in]  rebuild               Whether we're rebuilding the tables.
 *
 * @return 0 success, 1 VT integrity check failed, -1 error
 */
static int
update_nvts_from_osp_vts (element_t *get_vts_response,
                          const gchar *scanner_feed_version,
                          int rebuild)
{
  element_t vts, vt;
  GList *preferences;
  int count_modified_vts, count_new_vts;
  time_t feed_version_epoch;
  char *osp_vt_hash;
  batch_t *vt_refs_batch, *vt_sevs_batch;

  count_modified_vts = 0;
  count_new_vts = 0;

  feed_version_epoch = nvts_feed_version_epoch();

  vts = element_child (*get_vts_response, "vts");
  if (vts == NULL)
    {
      g_warning ("%s: VTS missing", __func__);
      return -1;
    }

  osp_vt_hash = element_attribute (vts, "sha256_hash");

  sql_begin_immediate ();
  prepare_nvts_insert (rebuild);

  vt_refs_batch = batch_start (vt_ref_insert_size);
  vt_sevs_batch = batch_start (vt_sev_insert_size);
  vt = element_first_child (vts);
  while (vt)
    {
      nvti_t *nvti = nvti_from_vt (vt);

      if (nvti == NULL)
        continue;

      if (nvti_creation_time (nvti) > feed_version_epoch)
        count_new_vts += 1;
      else
        count_modified_vts += 1;

      insert_nvt (nvti, rebuild, vt_refs_batch, vt_sevs_batch);

      preferences = NULL;
      if (update_preferences_from_vt (vt, nvti_oid (nvti), &preferences))
        {
          sql_rollback ();
          return -1;
        }
      if (rebuild == 0)
        sql ("DELETE FROM nvt_preferences%s WHERE name LIKE '%s:%%';",
             rebuild ? "_rebuild" : "",
             nvti_oid (nvti));
      insert_nvt_preferences_list (preferences, rebuild);
      g_list_free_full (preferences, (GDestroyNotify) preference_free);

      nvti_free (nvti);
      vt = element_next (vt);
    }
  batch_end (vt_refs_batch);
  batch_end (vt_sevs_batch);

  finalize_nvts_insert (count_new_vts, count_modified_vts,scanner_feed_version,
                        rebuild);
  sql_commit ();

  if (osp_vt_hash && strcmp (osp_vt_hash, ""))
    {
      char *db_vts_hash;

      /*
       * The hashed string used for verifying the NVTs generated as follows:
       *
       * For each NVT, sorted by OID, concatenate:
       *   - the OID
       *   - the modification time as seconds since epoch
       *   - the preferences sorted as strings(!) and concatenated including:
       *     - the id
       *     - the name
       *     - the default value (including choices for the "radio" type)
       *
       * All values are concatenated without a separator.
       */
      db_vts_hash
        = sql_string ("SELECT encode ("
                      "  digest (vts_verification_str (), 'SHA256'),"
                      "  'hex'"
                      " );");

      if (strcmp (osp_vt_hash, db_vts_hash ? db_vts_hash : ""))
        {
          g_warning ("%s: SHA-256 hash of the VTs in the database (%s)"
                     " does not match the one from the scanner (%s).",
                     __func__, db_vts_hash, osp_vt_hash);

          g_free (osp_vt_hash);
          g_free (db_vts_hash);
          return 1;
        }

      g_free (db_vts_hash);
    }
  else
    g_warning ("%s: No SHA-256 hash received from scanner, skipping check.",
               __func__);

  g_free (osp_vt_hash);
  return 0;
}

/**
 * @brief File socket for OSP NVT update.
 */
static gchar *openvas_vt_update_socket = NULL;

/**
 * @brief Get the current file socket for OSP NVT update.
 *
 * @return The path of the file socket for OSP NVT update.
 */
const gchar *
get_osp_vt_update_socket ()
{
  return openvas_vt_update_socket;
}

/**
 * @brief Set the file socket for OSP NVT update.
 *
 * @param new_socket The new path of the file socket for OSP NVT update.
 */
void
set_osp_vt_update_socket (const char *new_socket)
{
  if (new_socket)
    {
      g_free (openvas_vt_update_socket);
      openvas_vt_update_socket = g_strdup (new_socket);
    }
}

/**
 * @brief Check the files socket used for OSP NVT update.
 *
 * @return 0 success, 1 no socket found.
 */
int
check_osp_vt_update_socket ()
{
  if (get_osp_vt_update_socket () == NULL)
    {
      char *default_socket;

      /* Try to get OSP VT update socket from default scanner. */

      default_socket = openvas_default_scanner_host ();
      if (default_socket == NULL)
        return 1;

      g_debug ("%s: Using OSP VT update socket from default OpenVAS"
               " scanner: %s",
               __func__,
               default_socket);
      set_osp_vt_update_socket (default_socket);
      free (default_socket);
    }

  return 0;
}

/**
 * @brief Get the VTs feed version from an OSP scanner.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 *
 * @return The feed version or NULL on error.
 */
char *
osp_scanner_feed_version (const gchar *update_socket)
{
  osp_connection_t *connection;
  gchar *error;
  gchar *scanner_feed_version;

  scanner_feed_version = NULL;

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s", __func__, update_socket);
      return NULL;
    }

  error = NULL;
  if (osp_get_vts_version (connection, &scanner_feed_version, &error))
    {
      if (error && strcmp (error, "OSPd OpenVAS is still starting") == 0)
        g_info ("%s: No feed version available yet. %s",
                __func__, error);
      else
        g_warning ("%s: failed to get scanner_feed_version. %s",
                   __func__, error ? : "");
      g_free (error);
      osp_connection_close (connection);
      return NULL;
    }

  osp_connection_close (connection);

  return scanner_feed_version;
}

/**
 * @brief Check VTs feed version status via OSP, optionally get versions.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 * @param[out] db_feed_version_out       Output of database feed version.
 * @param[out] scanner_feed_version_out  Output of scanner feed version.
 *
 * @return 0 VTs feed current, -1 error, 1 VT update needed.
 */
int
nvts_feed_version_status_internal_osp (const gchar *update_socket,
                                       gchar **db_feed_version_out,
                                       gchar **scanner_feed_version_out)
{
  gchar *db_feed_version = NULL;
  gchar *scanner_feed_version = NULL;

  if (db_feed_version_out)
    *db_feed_version_out = NULL;
  if (scanner_feed_version_out)
    *scanner_feed_version_out = NULL;

  db_feed_version = nvts_feed_version ();
  g_debug ("%s: db_feed_version: %s", __func__, db_feed_version);
  if (db_feed_version_out && db_feed_version)
    *db_feed_version_out = g_strdup (db_feed_version);

  scanner_feed_version = osp_scanner_feed_version (update_socket);

  g_debug ("%s: scanner_feed_version: %s", __func__, scanner_feed_version);
  if (scanner_feed_version == NULL) {
      g_free (db_feed_version);
      return -1;
  }

  if (scanner_feed_version_out && scanner_feed_version)
    *scanner_feed_version_out = g_strdup (scanner_feed_version);

  if ((db_feed_version == NULL)
      || strcmp (scanner_feed_version, db_feed_version))
    {
      g_free (db_feed_version);
      g_free (scanner_feed_version);
      return 1;
    }

  g_free (db_feed_version);
  g_free (scanner_feed_version);
  return 0;
}

/**
 * @brief Update scanner preferences via OSP.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 *
 * @return 0 success, -1 error.
 */
int
update_scanner_preferences_osp (const gchar *update_socket)
{
  GSList *scanner_prefs;
  osp_connection_t *connection;

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s ",
                __func__, update_socket);
      return -1;
    }

  scanner_prefs = NULL;
  if (osp_get_scanner_details (connection, NULL, &scanner_prefs))
    {
      g_warning ("%s: failed to get scanner preferences", __func__);
      osp_connection_close (connection);
      return -1;
    }
  else
    {
      GString *prefs_sql;
      GSList *point;
      int first;

      point = scanner_prefs;
      first = 1;

      osp_connection_close (connection);
      prefs_sql = g_string_new ("INSERT INTO nvt_preferences (name, value)"
                                " VALUES");
      while (point)
        {
          osp_param_t *param;
          gchar *quoted_name, *quoted_value;

          param = point->data;
          quoted_name = sql_quote (osp_param_id (param));
          quoted_value = sql_quote (osp_param_default (param));

          g_string_append_printf (prefs_sql,
                                  "%s ('%s', '%s')",
                                  first ? "" : ",",
                                  quoted_name,
                                  quoted_value);
          first = 0;
          point = g_slist_next (point);
          g_free (quoted_name);
          g_free (quoted_value);
        }
      g_string_append (prefs_sql,
                       " ON CONFLICT (name)"
                       " DO UPDATE SET value = EXCLUDED.value;");

      if (first == 0)
        {
          sql ("%s", prefs_sql->str);
        }

      g_string_free (prefs_sql, TRUE);
    }
  return 0;
}

/**
 * @brief Update VTs via OSP.
 *
 * @param[in]  update_socket         Socket to connect to.
 * @param[in]  db_feed_version       Feed version from meta table.
 * @param[in]  scanner_feed_version  Feed version from scanner.
 * @param[in]  rebuild               Whether to rebuild the NVT tables from scratch.
 *
 * @return 0 success, 1 VT integrity check failed, -1 error.
 */
int
update_nvt_cache_osp (const gchar *update_socket, gchar *db_feed_version,
                      gchar *scanner_feed_version, int rebuild)
{
  osp_connection_t *connection;
  element_t vts;
  osp_get_vts_opts_t get_vts_opts;
  time_t old_nvts_last_modified;
  int ret;
  char *str;

  if (rebuild
      || db_feed_version == NULL
      || strcmp (db_feed_version, "") == 0
      || strcmp (db_feed_version, "0") == 0)
    old_nvts_last_modified = 0;
  else
    old_nvts_last_modified
      = (time_t) sql_int64_0 ("SELECT max(modification_time) FROM nvts");

  /* Update NVTs. */

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s (2)", __func__,
                 update_socket);
      return -1;
    }

  get_vts_opts = osp_get_vts_opts_default;
  if (db_feed_version)
    get_vts_opts.filter = g_strdup_printf ("modification_time>%s", db_feed_version);
  else
    get_vts_opts.filter = NULL;

  if (osp_get_vts_ext_str (connection, get_vts_opts, &str))
    {
      g_warning ("%s: failed to get VTs", __func__);
      g_free (get_vts_opts.filter);
      g_free (str);
      return -1;
    }

  g_free (get_vts_opts.filter);

  if (parse_element (str, &vts))
    {
      g_warning ("%s: failed to parse VTs", __func__);
      g_free (str);
      return -1;
    }

  osp_connection_close (connection);
  ret = update_nvts_from_osp_vts (&vts, scanner_feed_version, rebuild);
  element_free (vts);
  g_free (str);
  if (ret)
    return ret;

  /* Update scanner preferences */
  ret = update_scanner_preferences_osp (update_socket);
  if (ret)
    return ret;

  update_nvt_end (old_nvts_last_modified);

  return 0;
}

/**
 * @brief Update or rebuild NVT db.
 *
 * Caller must get the lock.
 *
 * @param[in]  update  0 rebuild, else update.
 *
 * @return 0 success, -1 error, -1 no osp update socket, -2 could not connect
 *         to osp update socket, -3 failed to get scanner version
 */
int
update_or_rebuild_nvts_osp (int update)
{
  gchar *db_feed_version = NULL;
  gchar *scanner_feed_version = NULL;

  const char *osp_update_socket;
  osp_connection_t *connection;
  int ret;
  gchar *error;

  if (check_osp_vt_update_socket ())
    {
      g_warning ("No OSP VT update socket found."
               " Use --osp-vt-update or change the 'OpenVAS Default'"
               " scanner to use the main ospd-openvas socket.");
      return -1;
    }

  osp_update_socket = get_osp_vt_update_socket ();
  if (osp_update_socket == NULL)
    {
      g_warning ("No OSP VT update socket set.");
      return -1;
    }

  db_feed_version = nvts_feed_version ();
  g_debug ("%s: db_feed_version: %s", __func__, db_feed_version);

  connection = osp_connection_new (osp_update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("Failed to connect to %s.", osp_update_socket);
      return -2;
    }

  error = NULL;
  if (osp_get_vts_version (connection, &scanner_feed_version, &error))
    {
      g_warning ("Failed to get scanner_version. %s", error ? : "");
      g_free (error);
      return -3;
    }
  g_debug ("%s: scanner_feed_version: %s", __func__, scanner_feed_version);

  osp_connection_close (connection);

  if (update == 0)
    set_nvts_feed_version ("0");

  ret = update_nvt_cache_osp (osp_update_socket, NULL,
                              scanner_feed_version, update == 0);
  if (ret)
    {
      return -1;
    }
  return 0;
}

/**
 * @brief Update VTs via OSP.
 *
 * Expect to be called in the child after a fork.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 *
 * @return 0 success, -1 error, 1 VT integrity check failed.
 */
int
manage_update_nvt_cache_osp (const gchar *update_socket)
{
  gchar *db_feed_version, *scanner_feed_version;
  int ret;

  /* Try update VTs. */

  ret = nvts_feed_version_status_internal_osp (update_socket,
                                               &db_feed_version,
                                               &scanner_feed_version);
  if (ret == 1)
    {
      g_info ("OSP service has different VT status (version %s)"
              " from database (version %s, %i VTs). Starting update ...",
              scanner_feed_version, db_feed_version,
              sql_int ("SELECT count (*) FROM nvts;"));

      ret = update_nvt_cache_osp (update_socket, db_feed_version,
                                  scanner_feed_version, 0);
      g_free (db_feed_version);
      g_free (scanner_feed_version);
      return ret;
    }

  return ret;
}
