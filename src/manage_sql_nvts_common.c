/* Copyright (C) 2019-2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file manage_sql_nvts_common.c
 * @brief GVM management layer: Common NVT logic
 *
 * Shared NVT logic for the GVM management layer.
 */

#include "iterator.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "manage_sql_nvts_common.h"
#include "sql.h"

#include <gvm/base/cvss.h>


/* Headers from backend specific manage_xxx.c file. */

void
create_tables_nvt (const gchar *);


/* NVT related global options */

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_ref_insert_size = VT_REF_INSERT_SIZE_DEFAULT;

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_sev_insert_size = VT_SEV_INSERT_SIZE_DEFAULT;

static void
insert_nvt_preference (gpointer nvt_preference, gpointer rebuild)
{
  preference_t *preference;

  if (nvt_preference == NULL)
    return;

  preference = (preference_t*) nvt_preference;

  manage_nvt_preference_add (preference->name, preference->value,
                             preference->nvt_oid, preference->id,
                             preference->type, preference->pref_name,
                             GPOINTER_TO_INT (rebuild));
}

/**
 * @brief Inserts NVT preferences in DB from a list of nvt_preference_t structures.
 *
 * @param[in]  nvt_preferences_list  List of nvts to be inserted.
 * @param[in]  rebuild               Whether a rebuild is happening.
 */
void
insert_nvt_preferences_list (GList *nvt_preferences_list, int rebuild)
{
  g_list_foreach (nvt_preferences_list, insert_nvt_preference, GINT_TO_POINTER (rebuild));
}

/**
 * @brief File socket for OSP NVT update.
 */
static gchar *osp_vt_update_socket = NULL;

/**
 * @brief Get the current file socket for OSP NVT update.
 *
 * @return The path of the file socket for OSP NVT update.
 */
const gchar *
get_osp_vt_update_socket ()
{
  return osp_vt_update_socket;
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
      g_free (osp_vt_update_socket);
      osp_vt_update_socket = g_strdup (new_socket);
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
 * @brief Create an SQL batch.
 *
 * @param[in]  max  Max number of iterations.
 *
 * @return Freshly allocated batch.
 */
batch_t *
batch_start (int max)
{
  batch_t *b;
  b = g_malloc0 (sizeof (batch_t));
  b->sql = g_string_new ("");
  b->max = max;
  return b;
}

/**
 * @brief Check an SQL batch.
 *
 * @param[in]  b  Batch.
 *
 * @return 1 init b->str, 0 continue as normal.
 */
int
batch_check (batch_t *b)
{
  b->size++;

  if (b->size == 1)
    // First time, caller must init sql.
      return 1;

  if (b->max == 0)
    return 0;

  if (b->size > b->max) {
      sql ("%s", b->sql->str);

      b->size = 1;

      g_string_free (b->sql, TRUE);
      b->sql = g_string_new ("");

      // Batch just ran, caller must init sql again.
      return 1;
  }

  return 0;
}

/**
 * @brief End and free an SQL batch.
 *
 * @param[in]  b  Batch.
 */
void
batch_end (batch_t *b)
{
  if (b->size > 0) {
      g_string_append_printf (b->sql, ";");
      sql ("%s", b->sql->str);
  }
  g_string_free (b->sql, TRUE);
  g_free (b);
}

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
 * @brief Insert vt_severities for an NVT.
 *
 * @param[in]  nvti       NVT Information.
 * @param[in]  rebuild    True if rebuilding.
 * @param[in]  batch      Batch for inserts.
 *
 * @return Highest severity.
 */
static double
insert_vt_severities (const nvti_t *nvti, int rebuild, batch_t *batch)
{
  int i;
  double highest;

  if (rebuild == 0)
    sql ("DELETE FROM vt_severities%s where vt_oid = '%s';",
         rebuild ? "_rebuild" : "",
         nvti_oid (nvti));

  highest = 0;

  for (i = 0; i < nvti_vtseverities_len (nvti); i++)
    {
      vtseverity_t *severity;
      gchar *quoted_origin, *quoted_value;
      int comma;

      comma = 0;
      severity = nvti_vtseverity (nvti, i);
      quoted_origin = sql_quote (vtseverity_origin (severity) ?
                                 vtseverity_origin (severity) : "");
      quoted_value = sql_quote (vtseverity_value (severity) ?
                                 vtseverity_value (severity) : "");

      if (batch_check (batch))
        g_string_append_printf (batch->sql,
                                "INSERT into vt_severities%s (vt_oid, type, origin, date, score,"
                                "                             value)"
                                " VALUES",
                                rebuild ? "_rebuild" : "");
      else
        comma = 1;

      g_string_append_printf (batch->sql,
                              // Newline in case it gets logged.
                              "%s\n ('%s', '%s', '%s', %i, %0.1f, '%s')",
                              comma ? "," : "",
                              nvti_oid (nvti), vtseverity_type (severity),
                              quoted_origin, vtseverity_date (severity),
                              vtseverity_score (severity), quoted_value);

      if (vtseverity_score (severity) > highest)
        highest = vtseverity_score (severity);

      g_free (quoted_origin);
      g_free (quoted_value);
    }

  return highest;
}

/**
 * @brief Insert vt_refs for an NVT.
 *
 * @param[in]  nvti       NVT Information.
 * @param[in]  rebuild    True if rebuilding.
 * @param[in]  batch      Batch for inserts.
 */
static void
insert_vt_refs (const nvti_t *nvti, int rebuild, batch_t *batch)
{
  int i;

  if (rebuild == 0)
    sql ("DELETE FROM vt_refs%s where vt_oid = '%s';",
         rebuild ? "_rebuild" : "",
         nvti_oid (nvti));

  for (i = 0; i < nvti_vtref_len (nvti); i++)
    {
      vtref_t *ref;
      gchar *quoted_type, *quoted_id, *quoted_text;
      int comma;

      comma = 0;
      ref = nvti_vtref (nvti, i);
      quoted_type = sql_quote (vtref_type (ref));
      quoted_id = sql_quote (vtref_id (ref));
      quoted_text = sql_quote (vtref_text (ref) ? vtref_text (ref) : "");

      if (batch_check (batch))
        g_string_append_printf (batch->sql,
                                "INSERT into vt_refs%s (vt_oid, type, ref_id, ref_text)"
                                " VALUES",
                                rebuild ? "_rebuild" : "");
      else
        comma = 1;

      g_string_append_printf (batch->sql,
                              // Newline in case it gets logged.
                              "%s\n ('%s', '%s', '%s', '%s')",
                              comma ? "," : "",
                              nvti_oid (nvti), quoted_type, quoted_id, quoted_text);

      g_free (quoted_type);
      g_free (quoted_id);
      g_free (quoted_text);
    }
}

/**
 * @brief Insert an NVT.
 *
 * Always called within a transaction.
 *
 * @param[in]  nvti           NVT Information.
 * @param[in]  rebuild        True if rebuilding.
 * @param[in]  vt_refs_batch  Batch for vt_refs.
 * @param[in]  vt_sevs_batch  Batch for vt_severities.
 */
void
insert_nvt (const nvti_t *nvti, int rebuild, batch_t *vt_refs_batch,
            batch_t *vt_sevs_batch)
{
  gchar *qod_str, *qod_type, *cve;
  gchar *quoted_name, *quoted_summary, *quoted_insight, *quoted_affected;
  gchar *quoted_impact, *quoted_detection, *quoted_cve, *quoted_tag;
  gchar *quoted_qod_type, *quoted_family;
  gchar *quoted_solution, *quoted_solution_type, *quoted_solution_method;
  int qod;
  double highest;

  cve = nvti_refs (nvti, "cve", "", 0);

  quoted_name = sql_quote (nvti_name (nvti) ? nvti_name (nvti) : "");
  quoted_summary = sql_quote (nvti_summary (nvti) ? nvti_summary (nvti) : "");
  quoted_insight = sql_quote (nvti_insight (nvti) ? nvti_insight (nvti) : "");
  quoted_affected = sql_quote (nvti_affected (nvti) ?
                               nvti_affected (nvti) : "");
  quoted_impact = sql_quote (nvti_impact (nvti) ? nvti_impact (nvti) : "");

  quoted_cve = sql_quote (cve ? cve : "");
  g_free (cve);

  quoted_solution = sql_quote (nvti_solution (nvti) ?
                               nvti_solution (nvti) : "");
  quoted_solution_type = sql_quote (nvti_solution_type (nvti) ?
                                    nvti_solution_type (nvti) : "");
  quoted_solution_method = sql_quote (nvti_solution_method (nvti) ?
                                      nvti_solution_method (nvti) : "");
  quoted_detection = sql_quote (nvti_detection (nvti) ?
                                nvti_detection (nvti) : "");

  quoted_tag = sql_quote (nvti_tag (nvti) ?  nvti_tag (nvti) : "");

  qod_str = nvti_qod (nvti);
  qod_type = nvti_qod_type (nvti);

  if (qod_str == NULL || sscanf (qod_str, "%d", &qod) != 1)
    qod = qod_from_type (qod_type);

  quoted_qod_type = sql_quote (qod_type ? qod_type : "");

  quoted_family = sql_quote (nvti_family (nvti) ? nvti_family (nvti) : "");

  if ((rebuild == 0)
      && sql_int ("SELECT EXISTS (SELECT * FROM nvts WHERE oid = '%s');",
                  nvti_oid (nvti)))
    sql ("DELETE FROM nvts%s WHERE oid = '%s';",
         rebuild ? "_rebuild" : "",
         nvti_oid (nvti));

  insert_vt_refs (nvti, rebuild, vt_refs_batch);

  highest = insert_vt_severities (nvti, rebuild, vt_sevs_batch);

  sql ("INSERT into nvts%s (oid, name, summary, insight, affected,"
       " impact, cve, tag, category, family, cvss_base,"
       " creation_time, modification_time, uuid, solution_type,"
       " solution_method, solution, detection, qod, qod_type)"
       " VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s',"
       " '%s', %i, '%s', %0.1f, %i, %i, '%s', '%s', '%s', '%s', '%s', %d, '%s');",
       rebuild ? "_rebuild" : "",
       nvti_oid (nvti), quoted_name, quoted_summary, quoted_insight,
       quoted_affected, quoted_impact, quoted_cve, quoted_tag,
       nvti_category (nvti), quoted_family, highest,
       nvti_creation_time (nvti), nvti_modification_time (nvti),
       nvti_oid (nvti), quoted_solution_type, quoted_solution_method,
       quoted_solution, quoted_detection, qod, quoted_qod_type);

  g_free (quoted_name);
  g_free (quoted_summary);
  g_free (quoted_insight);
  g_free (quoted_affected);
  g_free (quoted_impact);
  g_free (quoted_cve);
  g_free (quoted_tag);
  g_free (quoted_family);
  g_free (quoted_solution);
  g_free (quoted_solution_type);
  g_free (quoted_solution_method);
  g_free (quoted_detection);
  g_free (quoted_qod_type);
}

/**
 * @brief Check that preference names are in the new format.
 *
 * @param[in]  table  Table name.
 */
void
check_old_preference_names (const gchar *table)
{
  /* 1.3.6.1.4.1.25623.1.0.14259:checkbox:Log nmap output
   * =>
   * 1.3.6.1.4.1.25623.1.0.14259:21:checkbox:Log nmap output */

  sql ("UPDATE %s"
       " SET name = nvt_preferences.name"
       " FROM nvt_preferences"
       " WHERE %s.name ~ '.*:.*:.*'"
       " AND nvt_preferences.name ~ '.*:.*:.*:.*'"
       " AND %s.name = regexp_replace (nvt_preferences.name,"
       "                               E'([^:]+):[^:]+:(.*)', '\\1:\\2');",
       table,
       table,
       table,
       table);
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
int
update_nvts_from_vts (element_t *get_vts_response,
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

  if (rebuild) {
    sql ("DROP TABLE IF EXISTS vt_refs_rebuild;");
    sql ("DROP TABLE IF EXISTS vt_severities_rebuild;");
    sql ("DROP TABLE IF EXISTS nvt_preferences_rebuild;");
    sql ("DROP TABLE IF EXISTS nvts_rebuild;");

    create_tables_nvt ("_rebuild");
  }
  else if (sql_int ("SELECT coalesce ((SELECT CAST (value AS INTEGER)"
                    "                  FROM meta"
                    "                  WHERE name = 'checked_preferences'),"
                    "                 0);")
           == 0)
    /* We're in the first NVT sync after migrating preference names.
     *
     * If a preference was removed from an NVT then the preference will be in
     * nvt_preferences in the old format, but we will not get a new version
     * of the preference name from the sync.  For example "Alle Dateien
     * Auflisten" was removed from 1.3.6.1.4.1.25623.1.0.94023.
     *
     * If a preference was not in the migrator then the new version of the
     * preference would be inserted alongside the old version, resulting in a
     * duplicate when the name of the old version was corrected.
     *
     * To solve both cases, we remove all nvt_preferences. */
    sql ("TRUNCATE nvt_preferences;");

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

  if (rebuild) {
    sql ("DROP VIEW IF EXISTS results_autofp;");
    sql ("DROP VIEW vulns;");
    sql ("DROP MATERIALIZED VIEW IF EXISTS result_vt_epss;");
    sql ("DROP TABLE nvts, nvt_preferences, vt_refs, vt_severities;");

    sql ("ALTER TABLE vt_refs_rebuild RENAME TO vt_refs;");
    sql ("ALTER TABLE vt_severities_rebuild RENAME TO vt_severities;");
    sql ("ALTER TABLE nvt_preferences_rebuild RENAME TO nvt_preferences;");
    sql ("ALTER TABLE nvts_rebuild RENAME TO nvts;");

    create_view_vulns ();

    create_indexes_nvt ();

    create_view_result_vt_epss ();
  }

  set_nvts_check_time (count_new_vts, count_modified_vts);

  set_nvts_feed_version (scanner_feed_version);

  if (check_config_families ())
    g_warning ("%s: Error updating config families."
               "  One or more configs refer to an outdated family of an NVT.",
               __func__);
  update_all_config_caches ();

  g_info ("Updating VTs in database ... %i new VTs, %i changed VTs",
          count_new_vts, count_modified_vts);

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
 * @brief Update config preferences where the name has changed in the NVTs.
 *
 * @param[in]  trash              Whether to update the trash table.
 * @param[in]  modification_time  Time NVTs considered must be modified after.
 */
void
check_preference_names (int trash, time_t modification_time)
{
  iterator_t prefs;

  sql_begin_immediate ();

  init_iterator (&prefs,
                 "WITH new_pref_matches AS"
                 " (SELECT substring (nvt_preferences.name,"
                 "                    '^([^:]*):') AS pref_nvt,"
                 "         CAST (substring (nvt_preferences.name,"
                 "                          '^[^:]*:([0-9]+):')"
                 "               AS integer) AS pref_id,"
                 "         name AS new_name,"
                 "         substring (nvt_preferences.name,"
                 "                    '^[^:]*:[0-9]+:[^:]*:(.*)')"
                 "           AS new_pref_name"
                 "     FROM nvt_preferences"
                 "    WHERE nvt_preferences.name ~ '^[^:]*:[0-9]+:[^:]*:.*'"
                 "      AND substr (name, 0, position (':' IN name))"
                 "          IN (SELECT oid FROM nvts"
                 "              WHERE modification_time > %ld))"
                 " SELECT c_prefs.id, c_prefs.name as old_name, new_name,"
                 "        configs%s.uuid AS config_id, new_pref_name"
                 "  FROM config_preferences%s AS c_prefs"
                 "  JOIN new_pref_matches"
                 "    ON c_prefs.pref_nvt = new_pref_matches.pref_nvt"
                 "   AND c_prefs.pref_id = new_pref_matches.pref_id"
                 "  JOIN configs%s ON configs%s.id = c_prefs.config"
                 " WHERE c_prefs.name != new_name;",
                 modification_time,
                 trash ? "_trash" : "",
                 trash ? "_trash" : "",
                 trash ? "_trash" : "",
                 trash ? "_trash" : "");

  while (next (&prefs))
    {
      resource_t preference;
      const char *old_name, *new_name, *config_id, *new_pref_name;
      gchar *quoted_new_name, *quoted_new_pref_name;

      preference = iterator_int64 (&prefs, 0);
      old_name = iterator_string (&prefs, 1);
      new_name = iterator_string (&prefs, 2);
      config_id = iterator_string (&prefs, 3);
      new_pref_name = iterator_string (&prefs, 4);

      g_message ("Preference '%s' of %sconfig %s changed to '%s'",
                 old_name,
                 trash ? "trash " : "",
                 config_id,
                 new_name);

      quoted_new_name = sql_quote (new_name);
      quoted_new_pref_name = sql_quote (new_pref_name);

      sql ("UPDATE config_preferences%s"
           " SET name = '%s', pref_name = '%s'"
           " WHERE id = %llu",
           trash ? "_trash " : "",
           quoted_new_name,
           quoted_new_pref_name,
           preference);

      g_free (quoted_new_name);
      g_free (quoted_new_pref_name);
    }

  sql_commit ();

  cleanup_iterator (&prefs);
}

/**
 * @brief Set the NVT update check time in the meta table.
 *
 * @param[in]  count_new       Number of new VTs with current update.
 * @param[in]  count_modified  Number of modified VTs with current update.
 */
void
set_nvts_check_time (int count_new, int count_modified)
{
  if (sql_int ("SELECT NOT EXISTS (SELECT * FROM meta"
               "                   WHERE name = 'nvts_check_time')"))
    sql ("INSERT INTO meta (name, value)"
         " VALUES ('nvts_check_time', m_now ());");
  else if (sql_int ("SELECT value = '0' FROM meta"
                    " WHERE name = 'nvts_check_time';"))
    sql ("UPDATE meta SET value = m_now ()"
         " WHERE name = 'nvts_check_time';");
  else
    {
      if (count_new > 0)
        event (EVENT_NEW_SECINFO, "nvt", 0, 0);

      if (count_modified > 0)
        event (EVENT_UPDATED_SECINFO, "nvt", 0, 0);

      sql ("UPDATE meta SET value = m_now ()"
           " WHERE name = 'nvts_check_time';");
    }
}
