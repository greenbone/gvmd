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
  gchar *quoted_cvss_base, *quoted_qod_type, *quoted_family, *value;
  gchar *quoted_solution, *quoted_solution_type;
  int creation_time, modification_time, qod, i;

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

  if (nvti_tag (nvti))
    {
      gchar **split, **point;
      GString *tag;

      /* creation_date=2009-04-09 14:18:58 +0200 (Thu, 09 Apr 2009)|... */

      split = g_strsplit (nvti_tag (nvti), "|", 0);
      point = split;

      while (*point)
        {
          if (((strlen (*point) > strlen ("creation_date"))
               && (strncmp (*point, "creation_date", strlen ("creation_date"))
                   == 0)
               && ((*point)[strlen ("creation_date")] == '='))
              || ((strlen (*point) > strlen ("last_modification"))
                  && (strncmp (*point, "last_modification",
                               strlen ("last_modification"))
                      == 0)
                  && ((*point)[strlen ("last_modification")] == '=')))
            {
              gchar **move;
              move = point;
              g_free (*point);
              while (*move)
                {
                  move[0] = move[1];
                  move++;
                }
            }
          else
            point++;
        }

      point = split;
      tag = g_string_new ("");
      while (*point)
        {
          if (point[1])
            g_string_append_printf (tag, "%s|", *point);
          else
            g_string_append_printf (tag, "%s", *point);
          point++;
        }
      g_strfreev (split);

      quoted_tag = sql_quote (tag->str);
      g_string_free (tag, TRUE);
    }
  else
    quoted_tag = g_strdup ("");

  quoted_cvss_base = sql_quote (nvti_cvss_base (nvti) ? nvti_cvss_base (nvti) : "");

  qod_str = tag_value (nvti_tag (nvti), "qod");
  qod_type = nvti_qod_type (nvti);

  if (qod_str == NULL || sscanf (qod_str, "%d", &qod) != 1)
    qod = qod_from_type (qod_type);

  quoted_qod_type = sql_quote (qod_type ? qod_type : "");

  g_free (qod_str);

  quoted_family = sql_quote (nvti_family (nvti) ? nvti_family (nvti) : "");

  value = tag_value (nvti_tag (nvti), "creation_date");
  switch (parse_time (value, &creation_time))
    {
      case -1:
        g_warning ("%s: Failed to parse creation time of %s: %s",
                   __FUNCTION__, nvti_oid (nvti), value);
        creation_time = 0;
        break;
      case -2:
        g_warning ("%s: Failed to make time: %s", __FUNCTION__, value);
        creation_time = 0;
        break;
      case -3:
        g_warning ("%s: Failed to parse timezone offset: %s",
                   __FUNCTION__,
                   value);
        creation_time = 0;
        break;
    }
  g_free (value);

  value = tag_value (nvti_tag (nvti), "last_modification");
  switch (parse_time (value, &modification_time))
    {
      case -1:
        g_warning ("%s: Failed to parse last_modification time of %s: %s",
                   __FUNCTION__, nvti_oid (nvti), value);
        modification_time = 0;
        break;
      case -2:
        g_warning ("%s: Failed to make time: %s", __FUNCTION__, value);
        modification_time = 0;
        break;
      case -3:
        g_warning ("%s: Failed to parse timezone offset: %s",
                   __FUNCTION__,
                   value);
        modification_time = 0;
        break;
    }
  g_free (value);

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
       nvti_category (nvti), quoted_family, quoted_cvss_base, creation_time,
       modification_time, nvti_oid (nvti), quoted_solution_type,
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
 * @brief Check for new NVTs after an update.
 */
static void
check_for_new_nvts ()
{
  if (sql_int ("SELECT EXISTS"
               " (SELECT * FROM nvts"
               "  WHERE oid NOT IN (SELECT oid FROM old_nvts));"))
    event (EVENT_NEW_SECINFO, "nvt", 0, 0);
}

/**
 * @brief Check for updated NVTS after an update.
 */
static void
check_for_updated_nvts ()
{
  if (sql_int ("SELECT EXISTS"
               " (SELECT * FROM nvts"
               "  WHERE modification_time > (SELECT modification_time"
               "                             FROM old_nvts"
               "                             WHERE old_nvts.oid = nvts.oid));"))
    event (EVENT_UPDATED_SECINFO, "nvt", 0, 0);
}

/**
 * @brief Set the NVT update check time in the meta table.
 */
static void
set_nvts_check_time ()
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
      check_for_new_nvts ();
      check_for_updated_nvts ();
      sql ("UPDATE meta SET value = m_now ()"
           " WHERE name = 'nvts_check_time';");
    }
}

/**
 * @brief Get tag field from VT.
 *
 * @param[in]  vt  VT.
 *
 * @return Freshly allocated string for tag field.
 */
static gchar *
get_tag (entity_t vt)
{
  entity_t child;
  GString *tag;
  int first;

  first = 1;
  tag = g_string_new ("");

  child = entity_child (vt, "creation_time");
  if (child)
    {
      g_string_append_printf (tag,
                              "%screation_date=%s",
                              first ? "" : "|",
                              entity_text (child));
      first = 0;
    }

  child = entity_child (vt, "modification_time");
  if (child)
    {
      g_string_append_printf (tag,
                              "%slast_modification=%s",
                              first ? "" : "|",
                              entity_text (child));
      first = 0;
    }

  child = entity_child (vt, "severities");
  if (child)
    {
      entity_t severity;

      severity = entity_child (child, "severity");
      if (severity
          && entity_attribute (severity, "type")
          && (strcmp (entity_attribute (severity, "type"),
                      "cvss_base_v2")
              == 0))
        {
          g_string_append_printf (tag,
                                  "%scvss_base_vector=%s",
                                  first ? "" : "|",
                                  entity_text (severity));
        }
      else
        g_warning ("%s: no severity", __FUNCTION__);
    }
  else
    g_warning ("%s: no severities", __FUNCTION__);

  return g_string_free (tag, FALSE);
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
  entity_t refs, ref, custom, family, category;
  entities_t children;
  gchar *tag, *cvss_base, *parsed_tags;

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

  tag = get_tag (vt);
  nvti_set_tag (nvti, tag);

  custom = entity_child (vt, "custom");
  if (custom == NULL)
    {
      g_warning ("%s: VT missing CUSTOM", __FUNCTION__);
      nvti_free (nvti);
      g_free (tag);
      return NULL;
    }

  family = entity_child (custom, "family");
  if (family == NULL)
    {
      g_warning ("%s: VT/CUSTOM missing FAMILY", __FUNCTION__);
      nvti_free (nvti);
      g_free (tag);
      return NULL;
    }
  nvti_set_family (nvti, entity_text (family));

  category = entity_child (custom, "category");
  if (category == NULL)
    {
      g_warning ("%s: VT/CUSTOM missing CATEGORY", __FUNCTION__);
      nvti_free (nvti);
      g_free (tag);
      return NULL;
    }
  nvti_set_category (nvti, atoi (entity_text (category)));

  parse_tags (tag, &parsed_tags, &cvss_base);

  nvti_set_cvss_base (nvti, cvss_base);

  g_free (parsed_tags);
  g_free (cvss_base);
  g_free (tag);

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

  vts = entity_child (*get_vts_response, "vts");
  if (vts == NULL)
    {
      g_warning ("%s: VTS missing", __FUNCTION__);
      return;
    }

  sql_begin_immediate ();

  sql ("CREATE TEMPORARY TABLE old_nvts"
       " (oid TEXT, modification_time INTEGER);");
  sql ("INSERT INTO old_nvts (oid, modification_time)"
       " SELECT oid, modification_time FROM nvts;");

  preferences = NULL;
  children = vts->entities;
  while ((vt = first_entity (children)))
    {
      nvti_t *nvti = nvti_from_vt (vt);

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

  set_nvts_check_time ();

  sql ("DROP TABLE old_nvts;");

  set_nvts_feed_version (scanner_feed_version);

  if (check_config_families ())
    g_warning ("%s: Error updating config families."
               "  One or more configs refer to an outdated family of an NVT.",
               __FUNCTION__);
  update_all_config_caches ();

  sql_commit ();
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

      get_vts_opts.filter = g_strdup_printf ("modification_time>%s", db_feed_version); 
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

      /* Tell the main process to update its NVTi cache. */
      sql ("UPDATE %s.meta SET value = 1 WHERE name = 'update_nvti_cache';",
           sql_schema ());

      g_info ("Updating VTs in database ... done (%i VTs).",
              sql_int ("SELECT count (*) FROM nvts;"));
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
