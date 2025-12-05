/* Copyright (C) 2019-2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Common NVT logic
 *
 * Shared NVT logic for the GVM management layer.
 */

#include "iterator.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "manage_sql_nvts_common.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Headers from backend specific manage_xxx.c file. */

void
create_tables_nvt (const gchar *);


/* NVT related global options */

/**
 * @brief Inserts an NVT preference into the database.
 *
 * @param[in] nvt_preference  Pointer to the preference structure.
 * @param[in] rebuild         Boolean (as gpointer) indicating whether
 *                            the database is being rebuilt.
 */
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
  g_list_foreach (nvt_preferences_list,
                  insert_nvt_preference,
                  GINT_TO_POINTER (rebuild));
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

/**
 * @brief Handles database state initialization before processing NVTs.
 *
 * @param[in] rebuild  Whether we're rebuilding the tables.
 */
void
prepare_nvts_insert (int rebuild) {
  if (rebuild) {
      sql("DROP TABLE IF EXISTS vt_refs_rebuild;");
      sql("DROP TABLE IF EXISTS vt_severities_rebuild;");
      sql("DROP TABLE IF EXISTS nvt_preferences_rebuild;");
      sql("DROP TABLE IF EXISTS nvts_rebuild;");

      create_tables_nvt("_rebuild");
  }
  else if (sql_int ("SELECT coalesce ((SELECT CAST (value AS INTEGER)"
                    "                  FROM meta"
                    "                  WHERE name = 'checked_preferences'),"
                    "                 0);")
           == 0)
    {
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
      sql("TRUNCATE nvt_preferences;");
  }
}

/**
 * @brief Finalizes the database update after processing NVTs.
 *
 * @param[in] count_new_vts         Number of newly added VTs.
 * @param[in] count_modified_vts    Number of modified VTs.
 * @param[in] nvts_feed_version     NVTs feed version.
 * @param[in] rebuild               Whether we are rebuilding tables.
 */
void
finalize_nvts_insert (int count_new_vts, int count_modified_vts,
                      const gchar *nvts_feed_version, int rebuild)
{
  if (rebuild) {
      sql("DROP VIEW IF EXISTS results_autofp;");
      sql("DROP VIEW vulns;");
      sql("DROP MATERIALIZED VIEW IF EXISTS result_vt_epss;");
      sql("DROP TABLE nvts, nvt_preferences, vt_refs, vt_severities;");
      sql("ALTER TABLE vt_refs_rebuild RENAME TO vt_refs;");
      sql("ALTER TABLE vt_severities_rebuild RENAME TO vt_severities;");
      sql("ALTER TABLE nvt_preferences_rebuild RENAME TO nvt_preferences;");
      sql("ALTER TABLE nvts_rebuild RENAME TO nvts;");

      create_view_vulns();
      create_indexes_nvt();
      create_view_result_vt_epss();
  }

  set_nvts_check_time(count_new_vts, count_modified_vts);

  if (nvts_feed_version)
    set_nvts_feed_version(nvts_feed_version);

  if (check_config_families())
    g_warning ("%s: Error updating config families."
               "  One or more configs refer to an outdated family of an NVT.",
               __func__);

  update_all_config_caches();

  g_info ("Updating VTs in database ... %i new VTs, %i changed VTs",
    count_new_vts, count_modified_vts);
}

/**
 * @brief Update NVT preferences from an NVTI structure
 *
 * @param[in]  nvti         NVTI structure.
 * @param[out] preferences  List of NVT preferences.
 *
 * @return 0 success, -1 error.
 */
int
update_preferences_from_nvti (nvti_t *nvti, GList **preferences)
{
  assert (preferences);

  int prefs_count = nvti_pref_len(nvti);
  for (int j = 0; j < prefs_count; j++)
    {
      int id;
      char *char_id, *type, *name, *def;
      const nvtpref_t *pref = NULL;

      pref = nvti_pref (nvti, j);

      id = nvtpref_id (pref);
      char_id = g_strdup_printf ("%d", id);
      type = g_strdup (nvtpref_type (pref));
      name = g_strdup (nvtpref_name (pref));
      def = g_strdup (nvtpref_default (pref));

      if (type == NULL)
        {
          GString *debug = g_string_new ("");
          g_warning ("%s: PARAM missing type attribute for OID: %s",
                     __func__, nvti_oid(nvti));
          g_string_free (debug, TRUE);
        }
      else if (id < 0)
        {
          GString *debug = g_string_new ("");
          g_warning ("%s: PARAM missing id attribute for OID: %s",
                     __func__, nvti_oid(nvti));
          g_string_free (debug, TRUE);
        }
      else if (name == NULL)
        {
          GString *debug = g_string_new ("");
          g_warning ("%s: PARAM missing NAME for OID: %s",
                     __func__, nvti_oid (nvti));
          g_string_free (debug, TRUE);
        }
      else
        {
          gchar *full_name;
          preference_t *preference;

          full_name = g_strdup_printf ("%s:%d:%s:%s",
                                       nvti_oid (nvti),
                                       id,
                                       type,
                                       name);

          blank_control_chars (full_name);
          preference = g_malloc0 (sizeof (preference_t));
          preference->free_strings = 1;
          preference->name = full_name;
          if (def)
            preference->value = g_strdup (def);
          else
            preference->value = g_strdup ("");
          preference->nvt_oid = g_strdup (nvti_oid (nvti));
          preference->id = g_strdup (char_id);
          preference->type = g_strdup (type);
          preference->pref_name = g_strdup (name);
          *preferences = g_list_prepend (*preferences, preference);
        }

      g_free (char_id);
      g_free (name);
      g_free (type);
      g_free (def);
    }

  return 0;
}

/**
 * @brief Updates report counts cache, config preferences and whole-only
 *        families after NVT sync.
 *
 * @param[in] old_nvts_last_modified  Time NVTs considered to be modified after.
 */
void
update_nvt_end (const time_t old_nvts_last_modified)
{

  time_t last_modified = old_nvts_last_modified;

  /* Update the cache of report counts. */
  reports_clear_count_cache_dynamic ();

  /* Tell the main process to update its NVTi cache. */
  sql ("UPDATE %s.meta SET value = 1 WHERE name = 'update_nvti_cache';",
        sql_schema ());

  g_info ("Updating VTs in database ... done (%i VTs).",
          sql_int ("SELECT count (*) FROM nvts;"));

  if (sql_int ("SELECT coalesce ((SELECT CAST (value AS INTEGER)"
                "                  FROM meta"
                "                  WHERE name = 'checked_preferences'),"
                "                 0);")
      == 0)
    {
      check_old_preference_names ("config_preferences");
      check_old_preference_names ("config_preferences_trash");

      /* Force update of names in new format in case hard-coded names
        * used by migrators are outdated */
      last_modified = 0;

      sql ("INSERT INTO meta (name, value)"
            " VALUES ('checked_preferences', 1)"
            " ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;");
    }

    check_preference_names (0, last_modified);
    check_preference_names (1, last_modified);

    check_whole_only_in_configs ();
}