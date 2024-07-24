/* Copyright (C) 2009-2022 Greenbone AG
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
 * @file manage_sql_nvts.c
 * @brief GVM management layer: NVTs
 *
 * The NVT parts of the GVM management layer.
 */

/**
 * @brief Enable extra GNU functions.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gvm/base/cvss.h>

#include "manage_sql_nvts.h"
#include "manage_preferences.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "manage_sql_secinfo.h"
#include "sql.h"
#include "utils.h"

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
 * @brief Max number of rows inserted per statement.
 */
static int vt_ref_insert_size = VT_REF_INSERT_SIZE_DEFAULT;

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_sev_insert_size = VT_SEV_INSERT_SIZE_DEFAULT;

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


/* NVT's. */

/**
 * @brief Set the VT ref insert size.
 *
 * @param new_size  New size.
 */
void
set_vt_ref_insert_size (int new_size)
{
  if (new_size < 0)
    vt_ref_insert_size = 0;
  else
    vt_ref_insert_size = new_size;
}

/**
 * @brief Set the VT severity insert size.
 *
 * @param new_size  New size.
 */
void
set_vt_sev_insert_size (int new_size)
{
  if (new_size < 0)
    vt_sev_insert_size = 0;
  else
    vt_sev_insert_size = new_size;
}

/**
 * @brief Ensures the sanity of nvts cache in DB.
 */
void
check_db_nvts ()
{
  /* Ensure the nvti cache update flag exists and is clear. */
  if (sql_int ("SELECT count(*) FROM %s.meta"
               " WHERE name = 'update_nvti_cache';",
               sql_schema ()))
    sql ("UPDATE %s.meta SET value = 0 WHERE name = 'update_nvti_cache';",
         sql_schema ());
  else
    sql ("INSERT INTO %s.meta (name, value)"
         " VALUES ('update_nvti_cache', 0);",
         sql_schema ());
}

/**
 * @brief Get the name of an NVT.
 *
 * @param[in]  nvt  NVT.
 *
 * @return Freshly allocated name of NVT if possible, else NULL.
 */
char *
manage_nvt_name (nvt_t nvt)
{
  return sql_string ("SELECT name FROM nvts WHERE id = %llu;", nvt);
}

/**
 * @brief Get the name of an NVT given its OID.
 *
 * @param[in]  oid  OID of NVT.
 *
 * @return Name of NVT if possible, else NULL.
 */
char *
nvt_name (const char *oid)
{
  gchar *quoted_oid = sql_quote (oid);
  char *ret = sql_string ("SELECT name FROM nvts WHERE oid = '%s' LIMIT 1;",
                          quoted_oid);
  g_free (quoted_oid);
  return ret;
}

/**
 * @brief Return feed version of the plugins in the plugin cache.
 *
 * @return Feed version of plugins if the plugins are cached, else NULL.
 */
char*
nvts_feed_version ()
{
  return sql_string ("SELECT value FROM %s.meta"
                     " WHERE name = 'nvts_feed_version';",
                     sql_schema ());
}

/**
 * @brief Return feed version of the plugins as seconds since epoch.
 *
 * @return Feed version in seconds since epoch of plugins.
 */
time_t
nvts_feed_version_epoch ()
{
  gchar *feed_version;
  struct tm tm;

  feed_version = nvts_feed_version ();

  if (feed_version == NULL)
    return 0;

  memset (&tm, 0, sizeof (struct tm));
  strptime (feed_version, "%Y%m%d%H%M%S", &tm);

  g_free (feed_version);

  return mktime (&tm);
}

/**
 * @brief Set the feed version of the plugins in the plugin cache.
 *
 * @param[in]  feed_version  New feed version.
 *
 * Also queue an update to the nvti cache.
 */
void
set_nvts_feed_version (const char *feed_version)
{
  gchar* quoted = sql_quote (feed_version);
  sql ("DELETE FROM %s.meta WHERE name = 'nvts_feed_version';",
       sql_schema ());
  sql ("INSERT INTO %s.meta (name, value)"
       " VALUES ('nvts_feed_version', '%s');",
       sql_schema (),
       quoted);
  g_free (quoted);
}

/**
 * @brief Find an NVT given an identifier.
 *
 * @param[in]   oid  An NVT identifier.
 * @param[out]  nvt  NVT return, 0 if successfully failed to find task.
 *
 * @return FALSE on success (including if failed to find NVT), TRUE on error.
 */
gboolean
find_nvt (const char* oid, nvt_t* nvt)
{
  gchar *quoted_oid;
  int ret;

  quoted_oid = sql_quote (oid);
  ret = sql_int64 (nvt,
                   "SELECT id FROM nvts WHERE oid = '%s';",
                   quoted_oid);
  g_free (quoted_oid);
  switch (ret)
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *nvt = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}

/**
 * @brief SQL batch.
 */
typedef struct
{
  GString *sql;  ///< SQL buffer.
  int max;       ///< Max number of inserts.
  int size;      ///< Number of inserts.
} batch_t;

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
 * @brief Insert an NVT.
 *
 * Always called within a transaction.
 *
 * @param[in]  nvti           NVT Information.
 * @param[in]  rebuild        True if rebuilding.
 * @param[in]  vt_refs_batch  Batch for vt_refs.
 * @param[in]  vt_sevs_batch  Batch for vt_severities.
 */
static void
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
 * @brief Initialise an NVT iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 * @param[in]  name        Name of the info
 *
 * @return 0 success, 1 failed to find NVT, 2 failed to find filter,
 *         -1 error.
 */
int
init_nvt_info_iterator (iterator_t* iterator, get_data_t *get, const char *name)
{
  static const char *filter_columns[] = NVT_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = NVT_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
    }
  else if (name)
    {
      gchar *quoted = sql_quote (name);
      clause = g_strdup_printf (" AND name = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by name, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }

  ret = init_get_iterator (iterator,
                           "nvt",
                           get,
                           /* Columns. */
                           columns,
                           /* Columns for trashcan. */
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           0);

  g_free (clause);
  return ret;
}

/**
 * @brief Initialise an NVT iterator not limited to a name.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find NVT, 2 failed to find filter,
 *         -1 error.
 */
int
init_nvt_info_iterator_all (iterator_t* iterator, get_data_t *get)
{
  return init_nvt_info_iterator(iterator, get, NULL);
}

/**
 * @brief Get NVT iterator SELECT columns.
 *
 * @return SELECT columns
 */
static gchar *
nvt_iterator_columns ()
{
  static column_t select_columns[] = NVT_ITERATOR_COLUMNS;
  static gchar *columns = NULL;
  if (columns == NULL)
    columns = columns_build_select (select_columns);
  return columns;
}

/**
 * @brief Get NVT iterator SELECT columns.
 *
 * @return SELECT columns
 */
static gchar *
nvt_iterator_columns_nvts ()
{
  static column_t select_columns[] = NVT_ITERATOR_COLUMNS_NVTS;
  static gchar *columns = NULL;
  if (columns == NULL)
    columns = columns_build_select (select_columns);
  return columns;
}

/**
 * @brief Count number of nvt.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of cpes in filtered set.
 */
int
nvt_info_count (const get_data_t *get)
{
  static const char *extra_columns[] = NVT_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = NVT_ITERATOR_COLUMNS;
  return count ("nvt", get, columns, NULL, extra_columns, 0, 0, 0,
                FALSE);
}

/**
 * @brief Count number of nvts created or modified after a given time.
 *
 * @param[in]  get            GET params.
 * @param[in]  count_time     Time NVTs must be created or modified after.
 * @param[in]  get_modified   Whether to get the modification time.
 *
 * @return Total number of nvts in filtered set.
 */
int
nvt_info_count_after (const get_data_t *get, time_t count_time,
                      gboolean get_modified)
{
  static const char *filter_columns[] = NVT_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = NVT_ITERATOR_COLUMNS;
  gchar *extra_where;
  int ret;

  if (get_modified)
    extra_where = g_strdup_printf (" AND modification_time > %ld"
                                   " AND creation_time <= %ld",
                                   count_time,
                                   count_time);
  else
    extra_where = g_strdup_printf (" AND creation_time > %ld",
                                   count_time);

  ret = count ("nvt", get, columns, NULL, filter_columns, 0, 0, extra_where,
               FALSE);

  g_free (extra_where);
  return ret;
}

/**
 * @brief Return SQL for selecting NVT's of a config from one family.
 *
 * @param[in]  config      Config.
 * @param[in]  family      Family to limit selection to.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "nvts.id".
 *
 * @return Freshly allocated SELECT statement on success, or NULL on error.
 */
static gchar *
select_config_nvts (const config_t config, const char* family, int ascending,
                    const char* sort_field)
{
  gchar *quoted_selector, *quoted_family, *sql;
  char *selector;

  selector = config_nvt_selector (config);
  if (selector == NULL)
    /* The config should always have a selector. */
    return NULL;

  quoted_selector = sql_quote (selector);
  free (selector);

  quoted_family = sql_quote (family);

  if (config_nvts_growing (config))
    {
      int constraining;

      /* The number of NVT's can increase. */

      constraining = config_families_growing (config);

      if (constraining)
        {
          /* Constraining the universe. */

          if (sql_int ("SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s';",
                       quoted_selector)
              == 1)
            /* There is one selector, it should be the all selector. */
            sql = g_strdup_printf
                   ("SELECT %s"
                    " FROM nvts WHERE family = '%s'"
                    " ORDER BY %s %s;",
                    nvt_iterator_columns (),
                    quoted_family,
                    sort_field ? sort_field : "name",
                    ascending ? "ASC" : "DESC");
          else
            {
              /* There are multiple selectors. */

              if (sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                           " WHERE name = '%s' AND exclude = 1"
                           " AND type = "
                           G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                           " AND family_or_nvt = '%s'"
                           ";",
                           quoted_selector,
                           quoted_family))
                /* The family is excluded, just iterate the NVT includes. */
                sql = g_strdup_printf
                       ("SELECT %s"
                        " FROM nvts, nvt_selectors"
                        " WHERE"
                        " nvts.family = '%s'"
                        " AND nvt_selectors.name = '%s'"
                        " AND nvt_selectors.family = '%s'"
                        " AND nvt_selectors.type = "
                        G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                        " AND nvt_selectors.exclude = 0"
                        " AND nvts.oid = nvt_selectors.family_or_nvt"
                        " ORDER BY %s %s;",
                        nvt_iterator_columns_nvts (),
                        quoted_family,
                        quoted_selector,
                        quoted_family,
                        sort_field ? sort_field : "nvts.name",
                        ascending ? "ASC" : "DESC");
              else
                /* The family is included.
                 *
                 * Iterate all NVT's minus excluded NVT's. */
                sql = g_strdup_printf
                       ("SELECT %s"
                        " FROM nvts"
                        " WHERE family = '%s'"
                        " EXCEPT"
                        " SELECT %s"
                        " FROM nvt_selectors, nvts"
                        " WHERE"
                        " nvts.family = '%s'"
                        " AND nvt_selectors.name = '%s'"
                        " AND nvt_selectors.family = '%s'"
                        " AND nvt_selectors.type = "
                        G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                        " AND nvt_selectors.exclude = 1"
                        " AND nvts.oid = nvt_selectors.family_or_nvt"
                        " ORDER BY %s %s;",
                        nvt_iterator_columns (),
                        quoted_family,
                        nvt_iterator_columns_nvts (),
                        quoted_family,
                        quoted_selector,
                        quoted_family,
                        /* This works around "ERROR: missing FROM-clause" from
                         * Postgres when using nvts.name. */
                        sort_field && strcmp (sort_field, "nvts.name")
                         ? sort_field : "3", /* 3 is nvts.name. */
                        ascending ? "ASC" : "DESC");
            }
        }
      else
        {
          int all;

          /* Generating from empty. */

          all = sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                         " WHERE name = '%s' AND exclude = 0"
                         " AND type = "
                         G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                         " AND family_or_nvt = '%s';",
                         quoted_selector,
                         quoted_family);

          if (all)
            /* There is a family include for this family. */
            sql = g_strdup_printf
                   ("SELECT %s"
                    " FROM nvts"
                    " WHERE family = '%s'"
                    " EXCEPT"
                    " SELECT %s"
                    " FROM nvt_selectors, nvts"
                    " WHERE"
                    " nvts.family = '%s'"
                    " AND nvt_selectors.name = '%s'"
                    " AND nvt_selectors.family = '%s'"
                    " AND nvt_selectors.type = "
                    G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                    " AND nvt_selectors.exclude = 1"
                    " AND nvts.oid = nvt_selectors.family_or_nvt"
                    " ORDER BY %s %s;",
                    nvt_iterator_columns (),
                    quoted_family,
                    nvt_iterator_columns_nvts (),
                    quoted_family,
                    quoted_selector,
                    quoted_family,
                    /* This works around "ERROR: missing FROM-clause" from
                     * Postgres when using nvts.name. */
                    sort_field && strcmp (sort_field, "nvts.name")
                     ? sort_field : "3", /* 3 is nvts.name. */
                    ascending ? "ASC" : "DESC");
          else
            sql = g_strdup_printf
                   (" SELECT %s"
                    " FROM nvt_selectors, nvts"
                    " WHERE"
                    " nvts.family = '%s'"
                    " AND nvt_selectors.name = '%s'"
                    " AND nvt_selectors.family = '%s'"
                    " AND nvt_selectors.type = "
                    G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                    " AND nvt_selectors.exclude = 0"
                    " AND nvts.oid = nvt_selectors.family_or_nvt"
                    " ORDER BY %s %s;",
                    nvt_iterator_columns_nvts (),
                    quoted_family,
                    quoted_selector,
                    quoted_family,
                    sort_field ? sort_field : "nvts.name",
                    ascending ? "ASC" : "DESC");
        }
    }
  else
    {
      /* The number of NVT's is static.  Assume a simple list of NVT
       * includes. */

      sql = g_strdup_printf
             ("SELECT %s"
              " FROM nvt_selectors, nvts"
              " WHERE nvts.family = '%s'"
              " AND nvt_selectors.exclude = 0"
              " AND nvt_selectors.type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
              " AND nvt_selectors.name = '%s'"
              " AND nvts.oid = nvt_selectors.family_or_nvt"
              " ORDER BY %s %s;",
              nvt_iterator_columns_nvts (),
              quoted_family,
              quoted_selector,
              sort_field ? sort_field : "nvts.id",
              ascending ? "ASC" : "DESC");
    }

  g_free (quoted_selector);
  g_free (quoted_family);

  return sql;
}

/**
 * @brief Initialise an NVT iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  nvt         NVT to iterate over, all if 0.
 * @param[in]  config      Config to limit selection to.  NULL for all NVTs.
 *                         Overridden by \arg nvt.
 * @param[in]  family      Family to limit selection to.  NULL for all NVTs.
 *                         Overridden by \arg config.
 * @param[in]  category    Category to limit selection to.  NULL for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_nvt_iterator (iterator_t* iterator, nvt_t nvt, config_t config,
                   const char* family, const char *category, int ascending,
                   const char* sort_field)
{
  assert ((nvt && family) == 0);

  if (nvt)
    {
      gchar* sql;
      sql = g_strdup_printf ("SELECT %s"
                             " FROM nvts WHERE id = %llu;",
                             nvt_iterator_columns (),
                             nvt);
      init_iterator (iterator, "%s", sql);
      g_free (sql);
    }
  else if (config)
    {
      gchar* sql;
      if (family == NULL) abort ();
      sql = select_config_nvts (config, family, ascending, sort_field);
      if (sql)
        {
          init_iterator (iterator, "%s", sql);
          g_free (sql);
        }
      else
        init_iterator (iterator,
                       "SELECT %s"
                       " FROM nvts LIMIT 0;",
                       nvt_iterator_columns ());
    }
  else if (family)
    {
      gchar *quoted_family = sql_quote (family);
      init_iterator (iterator,
                     "SELECT %s"
                     " FROM nvts"
                     " WHERE family = '%s'"
                     " ORDER BY %s %s;",
                     nvt_iterator_columns (),
                     quoted_family,
                     sort_field ? sort_field : "name",
                     ascending ? "ASC" : "DESC");
      g_free (quoted_family);
    }
  else if (category)
    {
      gchar *quoted_category;
      quoted_category = sql_quote (category);
      init_iterator (iterator,
                     "SELECT %s"
                     " FROM nvts"
                     " WHERE category = '%s'"
                     " ORDER BY %s %s;",
                     nvt_iterator_columns (),
                     quoted_category,
                     sort_field ? sort_field : "name",
                     ascending ? "ASC" : "DESC");
      g_free (quoted_category);
    }
  else
    init_iterator (iterator,
                   "SELECT %s"
                   " FROM nvts"
                   " ORDER BY %s %s;",
                   nvt_iterator_columns (),
                   sort_field ? sort_field : "name",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Initialise an NVT iterator, for NVTs of a certain CVE.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cve         CVE name.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_cve_nvt_iterator (iterator_t* iterator, const char *cve, int ascending,
                       const char* sort_field)
{
  init_iterator (iterator,
                 "SELECT %s"
                 " FROM nvts"
                 " WHERE cve %s '%%%s, %%'"
                 "    OR cve %s '%%%s'"
                 " ORDER BY %s %s;",
                 nvt_iterator_columns (),
                 sql_ilike_op (),
                 cve ? cve : "",
                 sql_ilike_op (),
                 cve ? cve : "",
                 sort_field ? sort_field : "name",
                 ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the OID from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return OID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_oid, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the name from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_name, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the tag from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Tag, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_tag, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the category from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Category.
 */
int
nvt_iterator_category (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
  return ret;
}

/**
 * @brief Get the family from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Family, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_family, GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get the cvss_base from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Cvss_base, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_cvss_base, GET_ITERATOR_COLUMN_COUNT + 7);

/**
 * @brief Get the qod from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return QoD, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_qod, GET_ITERATOR_COLUMN_COUNT + 10);

/**
 * @brief Get the qod_type from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return QoD type, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_qod_type, GET_ITERATOR_COLUMN_COUNT + 11);

/**
 * @brief Get the solution_type from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Solution Type, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_solution_type, GET_ITERATOR_COLUMN_COUNT + 12);

/**
 * @brief Get the solution from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Solution, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_solution, GET_ITERATOR_COLUMN_COUNT + 14);

/**
 * @brief Get the summary from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Summary, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_summary, GET_ITERATOR_COLUMN_COUNT + 15);

/**
 * @brief Get the insight from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Insight, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_insight, GET_ITERATOR_COLUMN_COUNT + 16);

/**
 * @brief Get the affected from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Affected, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_affected, GET_ITERATOR_COLUMN_COUNT + 17);

/**
 * @brief Get the impact from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Impact, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_impact, GET_ITERATOR_COLUMN_COUNT + 18);

/**
 * @brief Get the detection from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Detection, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_detection, GET_ITERATOR_COLUMN_COUNT + 19);

/**
 * @brief Get the solution method from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Solution method, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_solution_method, GET_ITERATOR_COLUMN_COUNT + 20);

/**
 * @brief Get the EPSS score selected by severity from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The EPSS score.
 */
double
nvt_iterator_epss_score (iterator_t* iterator)
{
  double ret;
  if (iterator->done) return -1;
  ret = iterator_double (iterator, GET_ITERATOR_COLUMN_COUNT + 21);
  return ret;
}

/**
 * @brief Get the EPSS percentile selected by severity from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The EPSS percentile.
 */
double
nvt_iterator_epss_percentile (iterator_t* iterator)
{
  double ret;
  if (iterator->done) return -1;
  ret = iterator_double (iterator, GET_ITERATOR_COLUMN_COUNT + 22);
  return ret;
}

/**
 * @brief Get the CVE of the EPSS score by severity from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return CVE-ID of the EPSS score, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_epss_cve, GET_ITERATOR_COLUMN_COUNT + 23);

/**
 * @brief Get the maximum severity of CVEs with EPSS info from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity score.
 */
double
nvt_iterator_epss_severity (iterator_t* iterator)
{
  double ret;
  if (iterator->done) return -1;
  ret = iterator_double (iterator, GET_ITERATOR_COLUMN_COUNT + 24);
  return ret;
}

/**
 * @brief Get whether the NVT has a severity for the max severity EPSS score.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether the severity exists.
 */
gboolean
nvt_iterator_has_epss_severity (iterator_t* iterator)
{
  gboolean ret;
  if (iterator->done) return -1;
  ret = iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 24) != NULL;
  return ret;
}

/**
 * @brief Get the maximum EPSS score from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum EPSS score.
 */
double
nvt_iterator_max_epss_score (iterator_t* iterator)
{
  double ret;
  if (iterator->done) return -1;
  ret = iterator_double (iterator, GET_ITERATOR_COLUMN_COUNT + 25);
  return ret;
}

/**
 * @brief Get the maximum EPSS percentile from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum EPSS percentile.
 */
double
nvt_iterator_max_epss_percentile (iterator_t* iterator)
{
  double ret;
  if (iterator->done) return -1;
  ret = iterator_double (iterator, GET_ITERATOR_COLUMN_COUNT + 26);
  return ret;
}

/**
 * @brief Get the CVE of the maximum EPSS score from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return CVE-ID of the maximum EPSS score, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_max_epss_cve, GET_ITERATOR_COLUMN_COUNT + 27);

/**
 * @brief Get the severity of the maximum EPSS score from an NVT iterator.
 * @param[in]  iterator  Iterator.
 *
 * @return The severity score.
 */
double
nvt_iterator_max_epss_severity (iterator_t* iterator)
{
  double ret;
  if (iterator->done) return -1;
  ret = iterator_double (iterator, GET_ITERATOR_COLUMN_COUNT + 28);
  return ret;
}

/**
 * @brief Get whether the NVT has a severity for the max EPSS score.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether the severity exists.
 */
gboolean
nvt_iterator_has_max_epss_severity (iterator_t* iterator)
{
  gboolean ret;
  if (iterator->done) return -1;
  ret = iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 28) != NULL;
  return ret;
}

/**
 * @brief Get the default timeout of an NVT.
 *
 * @param[in]  oid  The OID of the NVT to get the timeout of.
 *
 * @return  Newly allocated string of the timeout in seconds or NULL.
 */
char *
nvt_default_timeout (const char* oid)
{
  return sql_string ("SELECT value FROM nvt_preferences"
                     " WHERE name = '%s:0:entry:timeout'",
                     oid);
}

/**
 * @brief Get the family of an NVT.
 *
 * @param[in]  oid  The OID of the NVT.
 *
 * @return Newly allocated string of the family, or NULL.
 */
char *
nvt_family (const char *oid)
{
  gchar *quoted_oid;
  char *ret;

  quoted_oid = sql_quote (oid);
  ret = sql_string ("SELECT family FROM nvts WHERE oid = '%s' LIMIT 1;",
                    quoted_oid);
  g_free (quoted_oid);
  return ret;
}

/**
 * @brief Get the number of NVTs in one or all families.
 *
 * @param[in]  family  Family name.  NULL for all families.
 *
 * @return Number of NVTs in family, or total number of nvts.
 */
int
family_nvt_count (const char *family)
{
  gchar *quoted_family;

  if (family == NULL)
    {
      static int nvt_count = -1;
      if (nvt_count == -1)
        nvt_count = sql_int ("SELECT COUNT(*) FROM nvts"
                             " WHERE family != 'Credentials';");
      return nvt_count;
    }

  quoted_family = sql_quote (family);
  int ret = sql_int ("SELECT COUNT(*) FROM nvts WHERE family = '%s';",
                     quoted_family);
  g_free (quoted_family);
  return ret;
}

/**
 * @brief Get the number of families.
 *
 * @return Total number of families.
 */
int
family_count ()
{
  return sql_int ("SELECT COUNT(distinct family) FROM nvts"
                  " WHERE family != 'Credentials';");
}

/**
 * @brief Insert a NVT preferences.
 *
 * @param[in] nvt_preference  Preference.
 * @param[in] rebuild         Whether a rebuild is happening.
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
static void
insert_nvt_preferences_list (GList *nvt_preferences_list, int rebuild)
{
  g_list_foreach (nvt_preferences_list, insert_nvt_preference, GINT_TO_POINTER (rebuild));
}

/**
 * @brief Set the NVT update check time in the meta table.
 *
 * @param[in]  count_new       Number of new VTs with current update.
 * @param[in]  count_modified  Number of modified VTs with current update.
 */
static void
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
 * @brief Check that preference names are in the new format.
 *
 * @param[in]  table  Table name.
 */
static void
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
static void
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
 * @brief Initialise an NVT severity iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  oid       OID of NVT.
 */
void
init_nvt_severity_iterator (iterator_t* iterator, const char *oid)
{
  gchar *quoted_oid;
  quoted_oid = sql_quote (oid ? oid : "");

  init_iterator (iterator,
                 "SELECT type, origin, iso_time(date), score, value"
                 " FROM vt_severities"
                 " WHERE vt_oid = '%s'",
                 quoted_oid);

  g_free (quoted_oid);
}

/**
 * @brief Gets the type from an NVT severity iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The type of the severity.
 */
DEF_ACCESS (nvt_severity_iterator_type, 0)

/**
 * @brief Gets the origin from an NVT severity iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The origin of the severity.
 */
DEF_ACCESS (nvt_severity_iterator_origin, 1);

/**
 * @brief Gets the date from an NVT severity iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The date of the severity in ISO time format.
 */
DEF_ACCESS (nvt_severity_iterator_date, 2);

/**
 * @brief Gets the score from an NVT severity iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The score of the severity.
 */
double
nvt_severity_iterator_score (iterator_t *iterator)
{
  return iterator_double (iterator, 3);
}

/**
 * @brief Gets the value from an NVT severity iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the severity in ISO time format.
 */
DEF_ACCESS (nvt_severity_iterator_value, 4);

/**
 * @brief Update VTs via OSP.
 *
 * @param[in]  update_socket         Socket to use to contact scanner.
 * @param[in]  db_feed_version       Feed version from meta table.
 * @param[in]  scanner_feed_version  Feed version from scanner.
 * @param[in]  rebuild               Whether to rebuild the NVT tables from scratch.
 *
 * @return 0 success, 1 VT integrity check failed, -1 error.
 */
static int
update_nvt_cache_osp (const gchar *update_socket, gchar *db_feed_version,
                      gchar *scanner_feed_version, int rebuild)
{
  osp_connection_t *connection;
  GSList *scanner_prefs;
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
  ret = update_nvts_from_vts (&vts, scanner_feed_version, rebuild);
  element_free (vts);
  g_free (str);
  if (ret)
    return ret;

  /* Update scanner preferences */

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s (3)",
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
      old_nvts_last_modified = 0;

      sql ("INSERT INTO meta (name, value)"
           " VALUES ('checked_preferences', 1)"
           " ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;");
    }

  check_preference_names (0, old_nvts_last_modified);
  check_preference_names (1, old_nvts_last_modified);

  check_whole_only_in_configs ();

  return 0;
}

/**
 * @brief Get the VTs feed version from an OSP scanner.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 *
 * @return The feed version or NULL on error.
 */
static char *
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
static int
nvts_feed_version_status_internal (const gchar *update_socket,
                                   gchar **db_feed_version_out,
                                   gchar **scanner_feed_version_out)
{
  gchar *db_feed_version, *scanner_feed_version;

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
 * @brief Check VTs feed version status
 *
 * @return 0 VTs feed current, 1 VT update needed, -1 error.
 */
int
nvts_feed_version_status ()
{
  return nvts_feed_version_status_internal (get_osp_vt_update_socket (),
                                            NULL,
                                            NULL);
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

  /* Re-open DB after fork. */

  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  /* Try update VTs. */

  ret = nvts_feed_version_status_internal (update_socket,
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

/**
 * @brief Sync NVTs if newer NVTs are available.
 *
 * @param[in]  fork_update_nvt_cache  Function to do the update.
 *
 * @return PID of the forked process handling the VTs sync, -1 on error.
 */
pid_t
manage_sync_nvts (int (*fork_update_nvt_cache) (pid_t*))
{
  pid_t child_pid = -1;
  fork_update_nvt_cache (&child_pid);
  return child_pid;
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
update_or_rebuild_nvts (int update)
{
  const char *osp_update_socket;
  gchar *db_feed_version, *scanner_feed_version;
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

  ret = update_nvt_cache_osp (osp_update_socket, NULL, scanner_feed_version, update == 0);
  if (ret)
    {
      return -1;
    }

  return 0;
}

/**
 * @brief Rebuild NVT db.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return 0 success, 1 VT integrity check failed, -1 error,
 *         -2 database is too old,
 *         -3 database needs to be initialised from server,
 *         -5 database is too new, -6 sync active.
 */
int
manage_rebuild (GSList *log_config, const db_conn_info_t *database)
{
  int ret;
  static lockfile_t lockfile;

  g_info ("   Rebuilding NVTs.");

  switch (feed_lockfile_lock_timeout (&lockfile))
    {
      case 1:
        printf ("A feed sync is already running.\n");
        return -6;
      case -1:
        printf ("Error getting sync lock.\n");
        return -1;
    }

  ret = manage_option_setup (log_config, database);
  if (ret)
    {
      feed_lockfile_unlock (&lockfile);
      return ret;
    }

  sql_begin_immediate ();
  ret = update_or_rebuild_nvts (0);

  switch (ret)
    {
      case 0:
        sql_commit ();
        break;
      case -1:
        printf ("No OSP VT update socket found."
                " Use --osp-vt-update or change the 'OpenVAS Default'"
                " scanner to use the main ospd-openvas socket.\n");
        sql_rollback ();
        break;
      case -2:
        printf ("Failed to connect to OSP VT update socket.\n");
        sql_rollback ();
        break;
      case -3:
        printf ("Failed to get scanner_version.\n");
        sql_rollback ();
        break;
      default:
        printf ("Failed to update or rebuild nvts.\n");
        sql_rollback ();
        break;
    }

  if (ret == 0)
    update_scap_extra ();

  feed_lockfile_unlock (&lockfile);
  manage_option_cleanup ();

  return ret;
}

/**
 * @brief Dump the string used to calculate the VTs verification hash
 *  to stdout.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return 0 success, -1 error, -2 database is too old,
 *         -3 database needs to be initialised from server,
 *         -5 database is too new, -6 sync active.
 */
int
manage_dump_vt_verification (GSList *log_config,
                             const db_conn_info_t *database)
{
  int ret;
  static lockfile_t lockfile;
  char *verification_str;

  switch (feed_lockfile_lock_timeout (&lockfile))
    {
      case 1:
        printf ("A feed sync is already running.\n");
        return -6;
      case -1:
        printf ("Error getting sync lock.\n");
        return -1;
    }

  ret = manage_option_setup (log_config, database);
  if (ret)
    {
      feed_lockfile_unlock (&lockfile);
      return ret;
    }

  verification_str = sql_string ("SELECT vts_verification_str ();");
  printf ("%s\n", verification_str);

  feed_lockfile_unlock (&lockfile);
  manage_option_cleanup ();

  return 0;
}

/**
 * @brief Cleans up NVT related id sequences likely to run out.
 *
 * @return 0 success, -1 error.
 */
int
cleanup_nvt_sequences () {
  g_info ("Cleaning up NVT related id sequences...");
  sql_begin_immediate ();

  if (cleanup_ids_for_table ("nvts"))
    {
      sql_rollback ();
      return -1;
    }
  g_info ("Updating nvt references in tags to new row ids");
  sql ("UPDATE tag_resources"
       " SET resource = (SELECT id FROM nvts WHERE uuid = resource_uuid)"
       " WHERE resource_type = 'nvt';");
  sql ("UPDATE tag_resources_trash"
       " SET resource = (SELECT id FROM nvts WHERE uuid = resource_uuid)"
       " WHERE resource_type = 'nvt';");

  if (cleanup_ids_for_table ("vt_refs"))
    {
      sql_rollback ();
      return -1;
    }

  sql_commit ();
  return 0;
}
