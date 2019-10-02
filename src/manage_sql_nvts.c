/* Copyright (C) 2009-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gvm/base/cvss.h>

#include "manage_sql.h"
#include "manage_sql_nvts.h"
#include "sql.h"
#include "utils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Helper functions. */

/** @brief Replace any control characters in string with spaces.
 *
 * @param[in,out]  string  String to replace in.
 */
static void
blank_control_chars (char *string)
{
  for (; *string; string++)
    if (iscntrl (*string) && *string != '\n') *string = ' ';
}


/* NVT related global options */

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


/* NVT's. */

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
 * @brief Insert an NVT.
 *
 * @param[in]  nvti       NVT Information.
 */
static void
insert_nvt (const nvti_t *nvti)
{
  gchar *qod_str, *qod_type, *cve;
  gchar *quoted_name, *quoted_summary, *quoted_insight, *quoted_affected;
  gchar *quoted_impact, *quoted_detection, *quoted_cve, *quoted_tag;
  gchar *quoted_cvss_base, *quoted_qod_type, *quoted_family;
  gchar *quoted_solution, *quoted_solution_type;
  int qod, i;

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
  quoted_detection = sql_quote (nvti_detection (nvti) ?
                                nvti_detection (nvti) : "");

  quoted_tag = sql_quote (nvti_tag (nvti) ?  nvti_tag (nvti) : "");

  quoted_cvss_base = sql_quote (nvti_cvss_base (nvti) ? nvti_cvss_base (nvti) : "");

  qod_str = tag_value (nvti_tag (nvti), "qod");
  qod_type = nvti_qod_type (nvti);

  if (qod_str == NULL || sscanf (qod_str, "%d", &qod) != 1)
    qod = qod_from_type (qod_type);

  quoted_qod_type = sql_quote (qod_type ? qod_type : "");

  g_free (qod_str);

  quoted_family = sql_quote (nvti_family (nvti) ? nvti_family (nvti) : "");

  if (sql_int ("SELECT EXISTS (SELECT * FROM nvts WHERE oid = '%s');",
               nvti_oid (nvti)))
    sql ("DELETE FROM nvts WHERE oid = '%s';", nvti_oid (nvti));

  sql ("INSERT into nvts (oid, name, summary, insight, affected,"
       " impact, cve, tag, category, family, cvss_base,"
       " creation_time, modification_time, uuid, solution_type,"
       " solution, detection, qod, qod_type)"
       " VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s',"
       " '%s', %i, '%s', '%s', %i, %i, '%s', '%s', '%s', '%s', %d, '%s');",
       nvti_oid (nvti), quoted_name, quoted_summary, quoted_insight,
       quoted_affected, quoted_impact, quoted_cve, quoted_tag,
       nvti_category (nvti), quoted_family, quoted_cvss_base,
       nvti_creation_time (nvti), nvti_modification_time (nvti),
       nvti_oid (nvti), quoted_solution_type,
       quoted_solution, quoted_detection, qod, quoted_qod_type);

  sql ("DELETE FROM vt_refs where vt_oid = '%s';", nvti_oid (nvti));

  for (i = 0; i < nvti_vtref_len (nvti); i++)
    {
      vtref_t *ref;
      gchar *quoted_id, *quoted_text;

      ref = nvti_vtref (nvti, i);
      quoted_id = sql_quote (vtref_id (ref));
      quoted_text = sql_quote (vtref_text (ref) ? vtref_text (ref) : "");

      sql ("INSERT into vt_refs (vt_oid, type, ref_id, ref_text)"
           " VALUES ('%s', '%s', '%s', '%s');",
           nvti_oid (nvti), vtref_type (ref), quoted_id, quoted_text);

      g_free (quoted_id);
      g_free (quoted_text);
    }

  g_free (quoted_name);
  g_free (quoted_summary);
  g_free (quoted_insight);
  g_free (quoted_affected);
  g_free (quoted_impact);
  g_free (quoted_cve);
  g_free (quoted_tag);
  g_free (quoted_cvss_base);
  g_free (quoted_family);
  g_free (quoted_solution);
  g_free (quoted_solution_type);
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
      // FIX what for anyway?
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
                        // FIX PG "ERROR: missing FROM-clause" using nvts.name.
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
                    // FIX PG "ERROR: missing FROM-clause" using nvts.name.
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
                 " WHERE cve %s '%%%s%%'"
                 " ORDER BY %s %s;",
                 nvt_iterator_columns (),
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
                     " WHERE name = '%s:0:entry:Timeout'",
                     oid);
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
 * @param[in] dummy           Dummy arg for g_list_foreach.
 *
 */
static void
insert_nvt_preference (gpointer nvt_preference, gpointer dummy)
{
  preference_t *preference;

  if (nvt_preference == NULL)
    return;

  preference = (preference_t*) nvt_preference;
  manage_nvt_preference_add (preference->name, preference->value);
}

/**
 * @brief Inserts NVT preferences in DB from a list of nvt_preference_t structures.
 *
 * @param[in]  nvt_preferences_list     List of nvts to be inserted.
 */
static void
insert_nvt_preferences_list (GList *nvt_preferences_list)
{
  g_list_foreach (nvt_preferences_list, insert_nvt_preference, NULL);
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
update_preferences_from_vt (entity_t vt, const gchar *oid, GList **preferences)
{
  entity_t params, param;
  entities_t children;

  assert (preferences);

  params = entity_child (vt, "params");
  if (params == NULL)
    return 0;

  children = params->entities;
  while ((param = first_entity (children)))
    {
      if (strcasecmp (entity_name (param), "param") == 0)
        {
          const gchar *type, *id;
          entity_t name, def;

          type = entity_attribute (param, "type");
          id = entity_attribute (param, "id");
          name = entity_child (param, "name");
          def = entity_child (param, "default");

          if (type == NULL)
            {
              GString *debug = g_string_new ("");
              g_warning ("%s: PARAM missing type attribute", __FUNCTION__);
              print_entity_to_string (param, debug);
              g_warning ("%s: PARAM: %s", __FUNCTION__, debug->str);
              g_string_free (debug, TRUE);
            }
          else if (id == NULL)
            {
              GString *debug = g_string_new ("");
              g_warning ("%s: PARAM missing id attribute", __FUNCTION__);
              print_entity_to_string (param, debug);
              g_warning ("%s: PARAM: %s", __FUNCTION__, debug->str);
              g_string_free (debug, TRUE);
            }
          else if (name == NULL)
            {
              GString *debug = g_string_new ("");
              g_warning ("%s: PARAM missing NAME", __FUNCTION__);
              print_entity_to_string (param, debug);
              g_warning ("%s: PARAM: %s", __FUNCTION__, debug->str);
              g_string_free (debug, TRUE);
            }
          else
            {
              gchar *full_name;
              preference_t *preference;

              full_name = g_strdup_printf ("%s:%s:%s:%s",
                                           oid,
                                           id,
                                           type,
                                           entity_text (name));

              blank_control_chars (full_name);
              preference = g_malloc0 (sizeof (preference_t));
              preference->name = full_name;
              if (def)
                preference->value = g_strdup (entity_text (def));
              else
                preference->value = g_strdup ("");
              *preferences = g_list_prepend (*preferences, preference);
            }
        }

      children = next_entities (children);
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
nvti_from_vt (entity_t vt)
{
  nvti_t *nvti = nvti_new ();
  const char *id;
  entity_t name, summary, insight, affected, impact, detection, solution;
  entity_t creation_time, modification_time;
  entity_t refs, ref, custom, family, category;
  entity_t severities;

  entities_t children;

  id = entity_attribute (vt, "id");
  if (id == NULL)
    {
      g_warning ("%s: VT missing id attribute", __FUNCTION__);
      nvti_free (nvti);
      return NULL;
    }
  nvti_set_oid (nvti, id);

  name = entity_child (vt, "name");
  if (name == NULL)
    {
      g_warning ("%s: VT missing NAME", __FUNCTION__);
      nvti_free (nvti);
      return NULL;
    }
  nvti_set_name (nvti, entity_text (name));

  summary = entity_child (vt, "summary");
  if (summary)
    nvti_set_summary (nvti, entity_text (summary));

  insight = entity_child (vt, "insight");
  if (insight)
    nvti_set_insight (nvti, entity_text (insight));

  affected = entity_child (vt, "affected");
  if (affected)
    nvti_set_affected (nvti, entity_text (affected));

  impact = entity_child (vt, "impact");
  if (impact)
    nvti_set_impact (nvti, entity_text (impact));

  creation_time = entity_child (vt, "creation_time");
  if (creation_time)
    nvti_set_creation_time (nvti, strtol (entity_text (creation_time),
                                          NULL, 10));

  modification_time = entity_child (vt, "modification_time");
  if (modification_time)
    nvti_set_modification_time (nvti, strtol (entity_text (modification_time),
                                              NULL, 10));

  detection = entity_child (vt, "detection");
  if (detection)
    {
      nvti_set_detection (nvti, entity_text (detection));
      nvti_set_qod_type (nvti, entity_attribute (detection, "qod_type"));
    }

  solution = entity_child (vt, "solution");
  if (solution)
    {
      const gchar *type;

      nvti_set_solution (nvti, entity_text (solution));

      type = entity_attribute (solution, "type");
      if (type == NULL)
        g_debug ("%s: SOLUTION missing type", __FUNCTION__);
      else
        nvti_set_solution_type (nvti, type);
    }

  refs = entity_child (vt, "refs");
  if (refs == NULL)
    {
      g_warning ("%s: VT missing REFS", __FUNCTION__);
      nvti_free (nvti);
      return NULL;
    }

  children = refs->entities;
  while ((ref = first_entity (children)))
    {
      const gchar *ref_type;

      ref_type = entity_attribute (ref, "type");
      if (ref_type == NULL)
        {
          GString *debug = g_string_new ("");
          g_warning ("%s: REF missing type attribute", __FUNCTION__);
          print_entity_to_string (ref, debug);
          g_warning ("%s: ref: %s", __FUNCTION__, debug->str);
          g_string_free (debug, TRUE);
        }
      else
        {
          const gchar *ref_id;

          ref_id = entity_attribute (ref, "id");
          if (ref_id == NULL)
            {
              GString *debug = g_string_new ("");
              g_warning ("%s: REF missing id attribute", __FUNCTION__);
              print_entity_to_string (ref, debug);
              g_warning ("%s: ref: %s", __FUNCTION__, debug->str);
              g_string_free (debug, TRUE);
            }
          else
            {
              nvti_add_vtref (nvti, vtref_new (ref_type, ref_id, NULL));
            }
        }

      children = next_entities (children);
    }

  severities = entity_child (vt, "severities");
  if (severities)
    {
      entity_t severity;

      severity = entity_child (severities, "severity");
      if (severity
          && entity_attribute (severity, "type")
          && (strcmp (entity_attribute (severity, "type"),
                      "cvss_base_v2")
              == 0))
        {
          gchar * cvss_base;

          nvti_add_tag (nvti, "cvss_base_vector", entity_text (severity));

          cvss_base = g_strdup_printf ("%.1f",
            get_cvss_score_from_base_metrics (entity_text (severity)));
          nvti_set_cvss_base (nvti, cvss_base);
          g_free (cvss_base);
        }
      else
        g_warning ("%s: no severity", __FUNCTION__);
    }
  else
    g_warning ("%s: no severities", __FUNCTION__);

  custom = entity_child (vt, "custom");
  if (custom == NULL)
    {
      g_warning ("%s: VT missing CUSTOM", __FUNCTION__);
      nvti_free (nvti);
      return NULL;
    }

  family = entity_child (custom, "family");
  if (family == NULL)
    {
      g_warning ("%s: VT/CUSTOM missing FAMILY", __FUNCTION__);
      nvti_free (nvti);
      return NULL;
    }
  nvti_set_family (nvti, entity_text (family));

  category = entity_child (custom, "category");
  if (category == NULL)
    {
      g_warning ("%s: VT/CUSTOM missing CATEGORY", __FUNCTION__);
      nvti_free (nvti);
      return NULL;
    }
  nvti_set_category (nvti, atoi (entity_text (category)));

  return nvti;
}

/**
 * @brief Update NVTs from VTs XML.
 *
 * @param[in]  get_vts_response      OSP GET_VTS response.
 * @param[in]  scanner_feed_version  Version of feed from scanner.
 */
static void
update_nvts_from_vts (entity_t *get_vts_response,
                      const gchar *scanner_feed_version)
{
  entity_t vts, vt;
  entities_t children;
  GList *preferences;
  int count_modified_vts, count_new_vts;
  time_t feed_version_epoch;

  count_modified_vts = 0;
  count_new_vts = 0;

  feed_version_epoch = nvts_feed_version_epoch();

  vts = entity_child (*get_vts_response, "vts");
  if (vts == NULL)
    {
      g_warning ("%s: VTS missing", __FUNCTION__);
      return;
    }

  sql_begin_immediate ();

  if (sql_int ("SELECT coalesce ((SELECT CAST (value AS INTEGER)"
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

  preferences = NULL;
  children = vts->entities;
  while ((vt = first_entity (children)))
    {
      nvti_t *nvti = nvti_from_vt (vt);

      if (nvti_creation_time (nvti) > feed_version_epoch)
        count_new_vts += 1;
      else
        count_modified_vts += 1;

      insert_nvt (nvti);

      if (update_preferences_from_vt (vt, nvti_oid (nvti), &preferences))
        {
          sql_rollback ();
          return;
        }

      nvti_free (nvti);
      children = next_entities (children);
    }

  insert_nvt_preferences_list (preferences);
  g_list_free_full (preferences, g_free);

  set_nvts_check_time (count_new_vts, count_modified_vts);

  set_nvts_feed_version (scanner_feed_version);

  if (check_config_families ())
    g_warning ("%s: Error updating config families."
               "  One or more configs refer to an outdated family of an NVT.",
               __FUNCTION__);
  update_all_config_caches ();

  g_info ("Updating VTs in database ... %i new VTs, %i changed VTs",
          count_new_vts, count_modified_vts);

  sql_commit ();
}

/**
 * @brief Check that preference names are in the new format.
 *
 * @param[in]  table  Table name.
 */
static void
check_preference_names (const gchar *table)
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
 * @brief Update VTs via OSP.
 *
 * Expect to be called in the child after a fork.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 *
 * @return 0 success, -1 error, 2 scanner still loading.
 */
int
manage_update_nvt_cache_osp (const gchar *update_socket)
{
  osp_connection_t *connection;
  gchar *db_feed_version, *scanner_feed_version;

  /* Re-open DB after fork. */

  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  /* Try update VTs. */

  db_feed_version = nvts_feed_version ();
  g_debug ("%s: db_feed_version: %s", __FUNCTION__, db_feed_version);

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s", __FUNCTION__, update_socket);
      return -1;
    }

  if (osp_get_vts_version (connection, &scanner_feed_version))
    {
      g_warning ("%s: failed to get scanner_version", __FUNCTION__);
      return -1;
    }
  g_debug ("%s: scanner_feed_version: %s", __FUNCTION__, scanner_feed_version);

  osp_connection_close (connection);

  if ((db_feed_version == NULL)
      || strcmp (scanner_feed_version, db_feed_version))
    {
      GSList *scanner_prefs;
      entity_t vts;
      osp_get_vts_opts_t get_vts_opts;

      g_info ("OSP service has newer VT status (version %s) than in database (version %s, %i VTs). Starting update ...",
              scanner_feed_version, db_feed_version, sql_int ("SELECT count (*) FROM nvts;"));

      connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
      if (!connection)
        {
          g_warning ("%s: failed to connect to %s (2)", __FUNCTION__,
                     update_socket);
          return -1;
        }

      if (db_feed_version)
        get_vts_opts.filter = g_strdup_printf ("modification_time>%s", db_feed_version);
      else
        get_vts_opts.filter = NULL;
      if (osp_get_vts_ext (connection, get_vts_opts, &vts))
        {
          g_warning ("%s: failed to get VTs", __FUNCTION__);
          g_free (get_vts_opts.filter);
          return -1;
        }
      g_free (get_vts_opts.filter);

      osp_connection_close (connection);

      update_nvts_from_vts (&vts, scanner_feed_version);
      free_entity (vts);

      /* Update scanner preferences */
      connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
      if (!connection)
        {
          g_warning ("%s: failed to connect to %s (3)",
                    __FUNCTION__, update_socket);
          return -1;
        }

      scanner_prefs = NULL;
      if (osp_get_scanner_details (connection, NULL, &scanner_prefs))
        {
          g_warning ("%s: failed to get scanner preferences", __FUNCTION__);
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
          check_preference_names ("config_preferences");
          check_preference_names ("config_preferences_trash");

          sql ("INSERT INTO meta (name, value)"
               " VALUES ('checked_preferences', 1)"
               " ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;");
        }
    }

  return 0;
}

/**
 * @brief Sync NVTs if newer NVTs are available.
 *
 * @param[in]  fork_update_nvt_cache  Function to do the update.
 */
void
manage_sync_nvts (int (*fork_update_nvt_cache) ())
{
  fork_update_nvt_cache ();
}
