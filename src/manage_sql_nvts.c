/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: NVTs
 *
 * The NVT parts of the GVM management layer.
 */

/**
 * @brief Enable extra GNU functions.
 */
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define _FILE_OFFSET_BITS 64
#include <stdio.h>

#include <gvm/base/nvti.h>
#include "glibconfig.h"
#include "manage.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <gvm/util/jsonpull.h>
#include <gvm/util/compressutils.h>
#include <gvm/util/vtparser.h>
#include <gvm/base/cvss.h>

#include "manage_sql_nvts.h"
#include "manage_preferences.h"
#include "manage_runtime_flags.h"
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
 * @brief Whether to skip the update of the nvti cache.
 */
static gboolean skip_upd_nvti_cache = FALSE;

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_ref_insert_size = VT_REF_INSERT_SIZE_DEFAULT;

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_sev_insert_size = VT_SEV_INSERT_SIZE_DEFAULT;


/* NVT's. */

/**
 * @brief Set flag if to run update_nvti_cache () or not.
 *
 * The default value of the flag is FALSE.
 *
 * @param[in]  skip_upd_nvti_c  Value for the flag if to
 *                              skip the cache update or not.
 */
void
set_skip_update_nvti_cache (gboolean skip_upd_nvti_c)
{
  skip_upd_nvti_cache = skip_upd_nvti_c;
}

/**
 * @brief Check if to run update_nvti_cache () or not.
 *
 * @return TRUE skip update, FALSE don't skip update
 */
gboolean
skip_update_nvti_cache ()
{
  return skip_upd_nvti_cache;
}

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
 * @param[in]  sort_field  Field to sort on, or NULL for "name".
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
 * @brief Get the Discovery from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Discovery.
 */
int
nvt_iterator_discovery (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 29);
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
 * @brief Check VTs feed version status
 *
 * @return 0 VTs feed current, 1 VT update needed, -1 error.
 */
int
nvts_feed_version_status_from_scanner ()
{
  scanner_type_t sc_type = get_scanner_type_by_uuid (SCANNER_UUID_DEFAULT);
  switch (sc_type)
  {
    case SCANNER_TYPE_OPENVAS:
      return nvts_feed_version_status_internal_osp (get_osp_vt_update_socket (),
                                                    NULL,
                                                    NULL);
    case SCANNER_TYPE_OPENVASD:
      if (feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
        return nvts_feed_version_status_internal_openvasd (NULL, NULL);
      g_critical ("%s: Default scanner is an openvasd one,"
                  " but gvmd is not built to support this.",
                  __func__);
      return -1;

    default:
      g_critical ("%s: scanner type %d is not supported as default",
                  __func__, sc_type);
      return -1;
  }
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
 *         to update socket, -3 failed to get scanner version
 */
int
update_or_rebuild_nvts (int update)
{
  if (feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
    return update_or_rebuild_nvts_openvasd (update);
  else
    return update_or_rebuild_nvts_osp (update);
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

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    {
      feed_lockfile_unlock (&lockfile);
      return ret;
    }

  sql_begin_immediate ();
  if (feature_enabled (FEATURE_ID_VT_METADATA))
    {
      ret = manage_update_nvts_from_feed (TRUE);
      if (ret == 0)
        sql_commit ();
      else
        {
          printf ("Failed to rebuild nvts from feed.\n");
          sql_rollback ();
        }
    }
  else
    {
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
    }

  if (ret == 0)
    {
      update_scap_extra ();
      manage_discovery_nvts ();
    }

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

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
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

/**
 * @brief GET NVTs feed info timestamp, as a string.
 *
 * @return Timestamp of NVTs feed, NULL on error.
 */
gchar *
nvts_feed_info_timestamp ()
{
  GError *error;
  gchar *content, *feed_info_path, *timestamp;
  gsize len;
  GRegex *regex;

  error = NULL;

  feed_info_path = g_build_filename (GVM_NVT_DIR, "plugin_feed_info.inc",
                                     NULL);

  g_file_get_contents (feed_info_path, &content, &len,
                       &error);
  if (error)
    {
      g_warning ("%s: Failed to get NVTs feed timestamp: %s",
                 __func__, error->message);
      g_error_free (error);
      g_free (feed_info_path);
      return NULL;
    }

  regex = g_regex_new ("^PLUGIN_SET[ \t]*=[ \t]*\"([0-9]+)\"",
                       G_REGEX_MULTILINE, 0, NULL);
  if (regex == NULL)
    {
      g_warning ("%s: Failed to create regex for NVTs feed timestamp",
                 __func__);
      g_free (content);
      g_free (feed_info_path);
      return NULL;
    }

  GMatchInfo *match_info;
  timestamp = NULL;
  if (g_regex_match (regex, content, 0, &match_info))
    timestamp = g_match_info_fetch (match_info, 1);

  if (timestamp == NULL)
    g_warning ("%s: Failed to parse timestamp from %s", __func__,
               feed_info_path);

  g_debug ("%s: NVTs feed timestamp: %s", __func__, timestamp);

  g_match_info_free (match_info);
  g_regex_unref (regex);
  g_free (feed_info_path);
  g_free (content);

  return timestamp;
}

/**
 * @brief Get the NVTs feed file timestamp in seconds since epoch.
 *
 * @return Timestamp from feed, -1 on error.
 */
int
nvts_feed_info_epoch ()
{
  gchar *timestamp;
  time_t epoch_time;
  struct tm tm;

  timestamp = nvts_feed_info_timestamp ();

  if (timestamp == NULL)
    {
      g_warning ("%s: Error reading NVTs feed timestamp", __func__);
      return -1;
    }

  if (strlen (timestamp) < 12)
    {
      g_warning ("%s: feed timestamp too short: %s",
                  __func__, timestamp);
      g_free (timestamp);
      return -1;
    }

  memset (&tm, 0, sizeof (struct tm));
  if (strptime (timestamp, "%Y%m%d%H%M", &tm) == NULL)
    {
      g_warning ("%s: Failed to parse time", __func__);
      g_free (timestamp);
      return -1;
    }
  epoch_time = mktime (&tm);
  if (epoch_time == -1)
    {
      g_warning ("%s: Failed to make time", __func__);
      g_free (timestamp);
      return -1;
    }

  g_debug ("%s: NVTS feed info epoch: %ld", __func__, (long) epoch_time);
  g_free (timestamp);
  return epoch_time;
}

/**
 * @brief Gets the NVTS feed version status.
 *
 * @return 0 feed current, 1 update needed, 2 database missing,
 *         3 missing "last_update", -1 error.
 */
int
nvts_feed_version_status_from_timestamp ()
{
  int feed_info_timestamp;
  time_t feed_version_epoch;

  if (manage_nvts_loaded () == 0)
    return 2;

  feed_info_timestamp = nvts_feed_info_epoch ();
  if (feed_info_timestamp == -1)
    return -1;

  feed_version_epoch = nvts_feed_version_epoch ();

  if (feed_version_epoch == -1)
    return -1;
  else if (feed_version_epoch == 0)
    {
      g_warning ("%s: last nvts database update missing", __func__);
      return 3;
    }

  if (feed_version_epoch == feed_info_timestamp)
    return 0;

  if (feed_version_epoch > feed_info_timestamp)
    {
      g_warning ("%s: last nvts database update later than last feed update",
                  __func__);
      return -1;
    }

  return 1;
}


/**
 * @brief Aborts NVTS update.
 *
 * @param[in]  nvts_feed_file_version  NVTs feed file version.
 *
 */
static void
abort_nvts_update (const gchar* nvts_feed_file_version)
{
  g_info ("Aborting NVTS update.");

  set_nvts_feed_version (nvts_feed_file_version);

  sql("DROP TABLE IF EXISTS vt_refs_rebuild;");
  sql("DROP TABLE IF EXISTS vt_severities_rebuild;");
  sql("DROP TABLE IF EXISTS nvt_preferences_rebuild;");
  sql("DROP TABLE IF EXISTS nvts_rebuild;");
}

/**
 * @brief Update NVTs from a JSON file.
 *
 * @param[in]  full_path               Full path to JSON VT metadata file.
 * @param[in]  nvts_feed_file_version  NVTs feed file version.
 *
 * @return 0 success, -1 error.
 */
static int
update_nvts_from_json_file (const gchar *full_path,
                            const gchar *nvts_feed_file_version)
{
  int count_modified_vts, count_new_vts;
  batch_t *vt_refs_batch, *vt_sevs_batch;

  count_modified_vts = 0;
  count_new_vts = 0;

  gvm_json_pull_parser_t parser;
  gvm_json_pull_event_t event;
  FILE *nvts_file;
  time_t db_feed_version_epoch;
  GList *preferences;
  int ret;

  int fd = open (full_path, O_RDONLY);

  if (fd < 0)
  {
    g_warning ("%s: Failed to open NVT meta data file '%s': %s",
               __func__, full_path, strerror(errno));
    return -1;
  }

  g_info ("Updating %s", full_path);

  nvts_file = gvm_gzip_open_file_reader_fd (fd);
  if (nvts_file == NULL)
    {
      g_warning ("%s: Failed to open NVT file: %s",
                __func__,
                strerror (errno));
      return -1;
    }

  gvm_json_pull_parser_init_full (&parser, nvts_file,
                                  GVM_JSON_PULL_PARSE_BUFFER_LIMIT,
                                  GVM_JSON_PULL_READ_BUFFER_SIZE * 8);
  gvm_json_pull_event_init (&event);
  gvm_json_pull_parser_next (&parser, &event);

  prepare_nvts_insert (1);
  vt_refs_batch = batch_start (vt_ref_insert_size);
  vt_sevs_batch = batch_start (vt_sev_insert_size);

  db_feed_version_epoch = nvts_feed_version_epoch();

  if (event.type == GVM_JSON_PULL_EVENT_ARRAY_START)
    {
      g_info ("%s: Start parsing feed", __func__);
      nvti_t *nvti = NULL;
      sql_begin_immediate ();

      while ((ret = parse_vt_json (&parser, &event, &nvti)) != 1)
        {
          if (ret == -1)
            {
              g_warning ("%s: Error parsing VT item: %s",
                         __func__, event.error_message);
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (nvts_file);
              sql_rollback ();
              return -1;
            }

          if (nvti_creation_time (nvti) > db_feed_version_epoch)
            count_new_vts += 1;
          else
            count_modified_vts += 1;

          insert_nvt (nvti, 1, vt_refs_batch, vt_sevs_batch);

          preferences = NULL;
          if (update_preferences_from_nvti (nvti, &preferences))
            {
              gvm_json_pull_event_cleanup (&event);
              gvm_json_pull_parser_cleanup (&parser);
              fclose (nvts_file);
              sql_rollback ();
              return -1;
            }
          insert_nvt_preferences_list (preferences, 1);
          g_list_free_full (preferences, (GDestroyNotify) preference_free);
          g_free(nvti);
       }

      batch_end (vt_refs_batch);
      batch_end (vt_sevs_batch);

      g_info ("%s: Finalizing nvts insert", __func__);

      finalize_nvts_insert (count_new_vts, count_modified_vts,
                            nvts_feed_file_version, 1);
      sql_commit ();
    }
  else if (event.type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event.error_message);
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (nvts_file);
      return -1;
    }
  else
    {
      g_warning ("%s: File must contain a JSON array", __func__);
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (nvts_file);
      return -1;
    }

  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (nvts_file);
  return 0;
}

/**
 * @brief update scanner preferences.
 *
 * @return 0 success, -1 error.
 */
int
update_scanner_preferences ()
{
  int ret;

  g_info ("%s: Updating scanner preferences", __func__);

  scanner_type_t sc_type = get_scanner_type_by_uuid (SCANNER_UUID_DEFAULT);

  switch (sc_type)
    {
    case SCANNER_TYPE_OPENVAS:
      {
        if (check_osp_vt_update_socket ())
          {
            g_warning ("No OSP VT update socket found."
                       " Use --osp-vt-update or change the 'OpenVAS Default'"
                       " scanner to use the main ospd-openvas socket.");
            return -1;
          }

        const char *osp_update_socket = get_osp_vt_update_socket ();
        if (osp_update_socket == NULL)
          {
            g_warning ("No OSP VT update socket set.");
            return -1;
          }

        ret = update_scanner_preferences_osp (osp_update_socket);
        break;
      }
    case SCANNER_TYPE_OPENVASD:
      {
#if ENABLE_HTTP_SCANNER
        scanner_t scanner;

        if (find_resource_no_acl ("scanner", SCANNER_UUID_DEFAULT, &scanner))
          return -1;

        ret = update_scanner_preferences_openvasd (scanner);
        break;
#else
        g_critical ("%s: Default scanner is an openvasd one,"
                    " but gvmd is not built to support this.",
                    __func__);
        return -1;
#endif
      }

    default:
      g_critical ("%s: scanner type %d is not supported as default",
                  __func__, sc_type);
      return -1;
    }

  if (ret)
    {
      g_warning ("%s: Failed to update scanner preferences", __func__);
      return -1;
    }

  g_info ("%s: Updating scanner preferences done", __func__);
  return 0;
}

/**
 * @brief update NVTs from feed.
 *
 * @param[in]  db_feed_version         Database feed version.
 * @param[in]  nvts_feed_file_version  JSON file feed version.
 *
 * @return 0 success, -1 error.
 */
int
update_nvts_from_feed (gchar *db_feed_version,
                       gchar *nvts_feed_file_version)
{
  gchar *full_path;
  GStatBuf state;
  time_t old_nvts_last_modified;
  int ret;

  g_info ("%s: Updating NVTs from feed", __func__);

  full_path = g_build_filename (GVM_NVT_DIR,
                                "vt-metadata.json.gz",
                                NULL);

  if (g_stat (full_path, &state))
    {
      g_free (full_path);
      full_path = g_build_filename (GVM_NVT_DIR,
                                    "vt-metadata.json",
                                    NULL);
    }

  if (g_stat (full_path, &state))
    {
      g_warning ("%s: No JSON VT metadata file found at %s",
                 __func__,
                 full_path);
      g_free (full_path);
      return -1;
    }

  if ((manage_nvts_loaded () == 0)
      || db_feed_version == NULL
      || strcmp (db_feed_version, "") == 0
      || strcmp (db_feed_version, "0") == 0)
    old_nvts_last_modified = 0;
  else
    old_nvts_last_modified
      = (time_t) sql_int64_0 ("SELECT max(modification_time) FROM nvts");

  ret = update_nvts_from_json_file (full_path, nvts_feed_file_version);

  g_free (full_path);

  if (ret)
    {
      g_warning ("%s: Failed to update NVTs from feed", __func__);
      return -1;
    }

  ret = update_scanner_preferences ();

  if (ret)
    {
      g_warning ("%s: Failed to update scanner preferences", __func__);
      return -1;
    }

  update_nvt_end (old_nvts_last_modified);

  return 0;
}

/**
 * @brief Update NVT db from feed.
 *
 * @param[in] reset_nvts_db  Whether to reset nvts feed version.
 *
 * @return 0 success, -1 error.
 */
int
manage_update_nvts_from_feed (gboolean reset_nvts_db)
{

  int ret = 0;
  gchar *db_feed_version = NULL;
  gchar *nvts_feed_file_version = NULL;

  if (reset_nvts_db)
    set_nvts_feed_version ("0");

  db_feed_version = nvts_feed_version ();
  nvts_feed_file_version = nvts_feed_info_timestamp ();

  if (nvts_feed_file_version == NULL)
    {
      g_warning ("%s: Failed to get NVTs feed info timestamp", __func__);
      return -1;
    }

  ret = update_nvts_from_feed (db_feed_version,
                               nvts_feed_file_version);
  if (ret != 0)
    {
      g_warning ("%s: Failed to update NVTs from feed", __func__);
      abort_nvts_update (nvts_feed_file_version);
      g_free (db_feed_version);
      g_free (nvts_feed_file_version);
      return -1;
    }

  g_free (db_feed_version);
  g_free (nvts_feed_file_version);
  g_info ("%s: Updating NVTs from feed done", __func__);
  return ret;
}

/**
 * @brief Marks the given NVTs as discovery NVTs based on their OIDs.
 *
 * @param[in] oids  GSList of char* OID strings to be marked as discovery NVTs.
 */
static void
manage_mark_discovery_nvts_from_oid (GSList *oids)
{
  if (!oids)
    return;

  GString *in_clause = g_string_new (NULL);
  GSList *iter;

  for (iter = oids; iter; iter = iter->next)
    {
      const char *oid = iter->data;
      if (!oid)
        continue;

      gchar *quoted_oid = sql_insert (oid);

      if (in_clause->len > 0)
        g_string_append (in_clause, ",");

      g_string_append (in_clause, quoted_oid);
      g_free (quoted_oid);
    }

  if (in_clause->len > 0)
    {
      sql_begin_immediate ();
      sql ("UPDATE nvts "
           "   SET discovery = 1 "
           " WHERE oid IN (%s);",
           in_clause->str);
      sql_commit ();
    }

  g_string_free (in_clause, TRUE);
}

/**
 * @brief Marks all NVTs of a given configuration UUID as discovery NVTs.
 *
 * The allocated OID list is freed before returning.
 *
 * @param[in] config_uuid  The UUID of the scan configuration whose NVTs
 *                         should be marked as discovery.
 */
static void
manage_discovery_for_config_uuid (const char *config_uuid)
{
  GSList *oids = NULL;

  get_nvt_oids_from_config_uuid (config_uuid, &oids);
  if (!oids)
    return;

  manage_mark_discovery_nvts_from_oid (oids);
  g_slist_free_full (oids, g_free);
}

/**
 * @brief Updates discovery flags for NVTs in the predefined discovery configs.
 *
 */
void
manage_discovery_nvts ()
{
  g_info ("%s: Updating Discovery NVTs", __func__);

  manage_discovery_for_config_uuid (CONFIG_UUID_DISCOVERY);
  manage_discovery_for_config_uuid (CONFIG_UUID_HOST_DISCOVERY);
  manage_discovery_for_config_uuid (CONFIG_UUID_SYSTEM_DISCOVERY);

  g_info ("%s: Updating Discovery NVTs done", __func__);
}

/**
 * @brief Validates sort_field for nvts table
 *
 * @return 0 success, -1 invalid
 */
int
validate_nvts_sort_field (const char* sort_field)
{
  static const gchar* nvt_sort_fields[] = NVT_VALID_SORTBY_COLUMNS;

  g_warning("VALIDATING SORT_FIELD: %s", sort_field);

  if (vector_find_string (nvt_sort_fields, sort_field))
    return 0;

  return -1;
}
