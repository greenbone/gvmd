/* Copyright (C) 2019-2021 Greenbone Networks GmbH
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
 * @file manage_sql_configs.c
 * @brief GVM management layer: Config SQL
 *
 * The Config SQL for the GVM management layer.
 */

#include "manage_configs.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "manage_sql_nvts.h"
#include "sql.h"

#include <assert.h>
#include <errno.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>

#include <gvm/util/uuidutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Static headers for internal non-SQL functions. */

int
sync_configs_with_feed (gboolean);


/* Static headers. */

static int
switch_representation (config_t, int);

static void
update_config_caches (config_t);


/* Helpers. */

/**
 * @brief Test whether a string equal to a given string exists in an array.
 *
 * @param[in]  array   Array of gchar* pointers.
 * @param[in]  string  String.
 *
 * @return 1 if a string equal to \arg string exists in \arg array, else 0.
 */
static int
member (GPtrArray *array, const char *string)
{
  const gchar *item;
  int index = 0;
  while ((item = (gchar*) g_ptr_array_index (array, index++)))
    if (strcmp (item, string) == 0) return 1;
  return 0;
}


/* NVT selectors.  This is part of Configs.
 *
 * An NVT selector is a named selection of NVT's from the cache of all
 * NVT's.
 *
 * An NVT selector is made up of zero or more selectors.  The selectors
 * combine in id order to make a selection.  Depending on the choice
 * of selectors the selection can be static or growing.  A growing
 * selection can grow when new NVT's enter the NVT cache, either because it
 * selects new families or because it selects new NVT's within existing
 * families.
 *
 * There are three types of selectors that an NVT selector can contain.
 *
 *   1) The "all selector", which selects all families and all NVT's in
 *      those families.  The only way to construct the NVT selector so
 *      that it grows to includes new families, is to add this selector.
 *
 *   2) A "family" selector, which designates an entire family.
 *
 *   3) An "NVT" selector, which designates a single NVT.
 *
 *      The naming overlaps here.  It's a selector of type NVT, which is
 *      part of an "NVT selector" (a named collection of selectors).
 *
 * The family and NVT type selectors can either include or exclude the
 * designated NVT's.
 *
 * While the all selector provides a way to select every single NVT, the
 * empty NVT selector corresponds to an empty NVT set.
 *
 * The selectors provide a mechanism to select a wide range of NVT
 * combinations.  The mechanism allows for complex selections involving
 * redundant selectors.  The Manager, however, only implements a simple
 * subset of the possible combinations of selectors.  This simple subset
 * is split into two cases.
 *
 *   1) Constraining the universe.
 *
 *      The all selector and an optional exclude for each family,
 *      optional NVT includes in the excluded families, and optional NVT
 *      excludes in all other families.
 *
 *      This allows a growing collection of families, while any family
 *      can still have a static NVT selection.
 *
 *   2) Generating from empty.
 *
 *      An empty set of selectors with an optional include for each family,
 *      optional NVT excludes in the included families, and optional NVT
 *      includes in all other families.
 *
 *      This allows a static collection of families, while any family
 *      can still grow when new NVT's enter the family.
 *
 * Either case allows one or more NVT's to be excluded from the family, both
 * when the family is growing and when the family is static.
 */

/* These could handle strange cases, like when a family is
 * included then excluded, or all is included then later excluded.
 * However, GMP prevents those cases from occurring. */

/**
 * @brief Get the number of families selected by an NVT selector.
 *
 * A growing family which has all current NVT's excluded is still
 * considered as selected by the NVT selector.
 *
 * @param[in]  quoted_selector   SQL-quoted selector name.
 * @param[in]  families_growing  1 if families are growing, else 0.
 *
 * @return The number of families selected by an NVT selector.
 */
int
nvt_selector_family_count (const char* quoted_selector, int families_growing)
{
  if (families_growing)
    /* Assume the only family selectors are excludes. */
    return family_count ()
           - sql_int ("SELECT COUNT(distinct family_or_nvt) FROM nvt_selectors"
                      " WHERE name = '%s'"
                      " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                      " AND exclude = 0"
                      " LIMIT 1;",
                      quoted_selector);

  /* Assume that the only family selectors are includes, and that if a
   * selection has any NVT includes then it only has NVT includes. */
  return sql_int ("SELECT COUNT (DISTINCT family)"
                  " FROM (SELECT DISTINCT family FROM nvt_selectors"
                  "       WHERE name = '%s'"
                  "       AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                  "       AND exclude = 0"
                  "       UNION SELECT family FROM nvt_selectors"
                  "             WHERE name = '%s'"
                  "             AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                  "             AND exclude = 0"
                  "             AND family IS NOT NULL) AS subquery;",
                  quoted_selector,
                  quoted_selector);
}

/**
 * @brief Get the family growth status of an NVT selector.
 *
 * @param[in]  selector  NVT selector.
 *
 * @return 1 growing, 0 static.
 */
static int
nvt_selector_families_growing (const char* selector)
{
  gchar *quoted_selector;
  char *string;

  /* The number of families can only grow if there is selector that includes
   * all. */

  quoted_selector = sql_quote (selector);
  string = sql_string ("SELECT name FROM nvt_selectors"
                       " WHERE name = '%s'"
                       " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                       " AND exclude = 0"
                       " LIMIT 1;",
                       quoted_selector);
  g_free (quoted_selector);
  if (string == NULL) return 0;
  free (string);
  return 1;
}

/**
 * @brief Get the NVT growth status of an NVT selector.
 *
 * @param[in]  quoted_selector   SQL-quoted selector name.
 * @param[in]  families_growing  1 if families are growing, else 0.
 *
 * @return 1 growing, 0 static.
 */
static int
nvt_selector_nvts_growing_2 (const char* quoted_selector, int families_growing)
{
  if (families_growing)
    /* Assume the only family selectors are excludes. */
    return (family_count ()
            - sql_int ("SELECT COUNT(distinct family_or_nvt) FROM nvt_selectors"
                       " WHERE name = '%s'"
                       " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                       " AND exclude = 0"
                       " LIMIT 1;",
                       quoted_selector))
           > 0;

  /* Assume the only family selectors are includes. */
  return sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                  " AND exclude = 0"
                  " LIMIT 1;",
                  quoted_selector)
         > 0;
}

/** @todo Move these config functions to the config section. */

/**
 * @brief Get the NVT growth status of a config.
 *
 * @param[in]  config  Config.
 *
 * @return 1 growing, 0 static.
 */
int
config_nvts_growing (config_t config)
{
  return sql_int ("SELECT nvts_growing FROM configs"
                  " WHERE id = %llu;",
                  config);
}

/**
 * @brief Get the family growth status of a config.
 *
 * @param[in]  config  Config.
 *
 * @return 1 growing, 0 static.
 */
int
config_families_growing (config_t config)
{
  return sql_int ("SELECT families_growing FROM configs"
                  " WHERE id = %llu;",
                  config);
}

/**
 * @brief Initialise an NVT selector iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  selector  Name of single selector to iterate over, NULL for all.
 * @param[in]  config    Config to limit iteration to, 0 for all.
 * @param[in]  type      Type of selector.  All if config is given.
 */
void
init_nvt_selector_iterator (iterator_t* iterator, const char* selector,
                            config_t config, int type)
{
  gchar *sql;

  assert (selector ? config == 0 : (config ? selector == NULL : 1));
  assert (config ? type == NVT_SELECTOR_TYPE_ANY : (type >= 0 && type <= 2));

  if (selector)
    {
      gchar *quoted_selector = sql_quote (selector);
      sql = g_strdup_printf ("SELECT exclude, family_or_nvt, name, type"
                             " FROM nvt_selectors"
                             " WHERE name = '%s' AND type = %i;",
                             quoted_selector,
                             type);
      g_free (quoted_selector);
    }
  else if (config)
    sql = g_strdup_printf ("SELECT exclude, family_or_nvt, name, type"
                           " FROM nvt_selectors"
                           " WHERE name ="
                           " (SELECT nvt_selector FROM configs"
                           "  WHERE configs.id = %llu);",
                           config);
  else
    sql = g_strdup_printf ("SELECT exclude, family_or_nvt, name, type"
                           " FROM nvt_selectors"
                           " WHERE type = %i;",
                           type);
  init_iterator (iterator, "%s", sql);
  g_free (sql);
}

/**
 * @brief Get whether the selector rule is an include rule.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return -1 if iteration is complete, 1 if include, else 0.
 */
int
nvt_selector_iterator_include (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, 0);
  return ret == 0;
}

/**
 * @brief Get the NVT or family from an NVT selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT selector, or NULL if iteration is complete.
 */
DEF_ACCESS (nvt_selector_iterator_nvt, 1);

/**
 * @brief Get the name from an NVT selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT selector, or NULL if iteration is complete.
 */
DEF_ACCESS (nvt_selector_iterator_name, 2);

/**
 * @brief Get the type from an NVT selector.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return -1 if iteration is complete, 1 if include, else 0.
 */
int
nvt_selector_iterator_type (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, 3);
  return ret;
}

/**
 * @brief Initialise an NVT selector family iterator.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  all        True if families are growing in the selector, else 0.
 *                        Only considered with a selector.
 * @param[in]  selector   Name of NVT selector.  NULL for all families.
 * @param[in]  ascending  Whether to sort ascending or descending.
 */
void
init_family_iterator (iterator_t* iterator, int all, const char* selector,
                      int ascending)
{
  gchar *quoted_selector;

  if (selector == NULL)
    {
      init_iterator (iterator,
                     "SELECT distinct family FROM nvts"
                     " WHERE family != 'Credentials'"
                     " ORDER BY family %s;",
                     ascending ? "ASC" : "DESC");
      return;
    }

  quoted_selector = sql_quote (selector);
  if (all)
    /* Constraining the universe.  Presume there is a family exclude for
     * every NVT include. */
    init_iterator (iterator,
                   "SELECT distinct family FROM nvts"
                   " WHERE family != 'Credentials'"
                   " EXCEPT"
                   " SELECT distinct family FROM nvt_selectors"
                   " WHERE type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                   " AND exclude = 1"
                   " AND name = '%s'"
                   " UNION"
                   " SELECT distinct family FROM nvt_selectors"
                   " WHERE type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                   " AND exclude = 0"
                   " AND name = '%s'"
                   " ORDER BY 1 %s;", /* 1 is family. */
                   quoted_selector,
                   quoted_selector,
                   ascending ? "ASC" : "DESC");
  else
    /* Generating from empty.  Presume any exclude is covered by an include. */
    init_iterator (iterator,
                   "SELECT distinct family FROM nvt_selectors"
                   " WHERE (type = 1 OR type = 2) AND name = '%s'"
                   " AND family != 'Credentials'"
                   " ORDER BY 1 %s;", /* 1 is family. */
                   quoted_selector,
                   ascending ? "ASC" : "DESC");
  g_free (quoted_selector);
}

/**
 * @brief Get the name from a family iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (family_iterator_name, 0);

/**
 * @brief Get whether an NVT selector selects every NVT in a family.
 *
 * @param[in]  selector  NVT selector.
 * @param[in]  family    Family name.
 * @param[in]  all       True if selector is an "all" selector, else 0.
 *
 * @return 1 yes, 0 no.
 */
static int
nvt_selector_entire_and_growing (const char *selector,
                                 const char *family,
                                 int all)
{
  int ret;
  gchar *quoted_family;
  gchar *quoted_selector;

  quoted_selector = sql_quote (selector);
  quoted_family = sql_quote (family);

  if (all)
    {
      /* Constraining the universe. */

      ret = sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                     " WHERE name = '%s'"
                     " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                     " AND family_or_nvt = '%s'"
                     " AND exclude = 1"
                     " LIMIT 1;",
                     quoted_selector,
                     quoted_family);

      if (ret)
        /* There's an exclude for the family, so family is static. */
        ret = 0;
      else
        {
          ret = sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                         " WHERE name = '%s'"
                         " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                         " AND exclude = 1"
                         /* And NVT is in family. */
                         " AND EXISTS (SELECT * FROM nvts"
                         "             WHERE oid = family_or_nvt"
                         "             AND family = '%s')"
                         " LIMIT 1;",
                         quoted_selector,
                         quoted_family);
          if (ret)
            /* Growing, but some NVTs excluded. */
            ret = 0;
          else
            /* Growing, every NVT included. */
            ret = 1;
        }

      g_free (quoted_selector);
      g_free (quoted_family);

      return ret;
    }

  /* Generating from empty. */

  ret = sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                 " WHERE name = '%s'"
                 " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                 " AND family_or_nvt = '%s'"
                 " AND exclude = 0"
                 " LIMIT 1;",
                 quoted_selector,
                 quoted_family);

  if (ret)
    {
      if (sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                   " WHERE name = '%s'"
                   " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                   " AND exclude = 1"
                   /* And NVT is in family. */
                   " AND EXISTS (SELECT * FROM nvts"
                   "             WHERE oid = family_or_nvt"
                   "             AND family = '%s')"
                   " LIMIT 1;",
                   quoted_selector,
                   quoted_family))
        /* Growing, but some NVTs excluded. */
        ret = 0;
      else
        /* Growing, every NVT included. */
        ret = 1;
    }
  else
    /* Family is not included, so family is static. */
    ret = 0;

  g_free (quoted_selector);
  g_free (quoted_family);

  return ret;
}

/**
 * @brief Get whether an NVT selector family is growing.
 *
 * @param[in]  selector  NVT selector.
 * @param[in]  family    Family name.
 * @param[in]  all       True if selector is an "all" selector, else 0.
 *
 * @return 1 growing, 0 static.
 */
int
nvt_selector_family_growing (const char *selector,
                             const char *family,
                             int all)
{
  int ret;
  gchar *quoted_family;
  gchar *quoted_selector;

  quoted_selector = sql_quote (selector);
  quoted_family = sql_quote (family);

  if (all)
    {
      /* Constraining the universe.  It's static if there is a family
       * exclude. */

      ret = sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                     " WHERE name = '%s'"
                     " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                     " AND family_or_nvt = '%s'"
                     " AND exclude = 1"
                     " LIMIT 1;",
                     quoted_selector,
                     quoted_family);

      g_free (quoted_selector);
      g_free (quoted_family);

      return ret ? 0 : 1;
    }

  /* Generating from empty.  It's growing if there is a family include. */

  ret = sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                 " WHERE name = '%s'"
                 " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                 " AND family_or_nvt = '%s'"
                 " AND exclude = 0"
                 " LIMIT 1;",
                 quoted_selector,
                 quoted_family);

  g_free (quoted_selector);
  g_free (quoted_family);

  return ret ? 1 : 0;
}

/**
 * @brief Get the number of NVTs selected by an NVT selector.
 *
 * @param[in]  selector  NVT selector.
 * @param[in]  family    Family name.  NULL for all.
 * @param[in]  growing   True if the given family is growing, else 0.
 *                       If family is NULL, true if the the families
 *                       are growing, else 0.
 *
 * @return Number of NVTs selected in one or all families.
 */
int
nvt_selector_nvt_count (const char *selector,
                        const char *family,
                        int growing)
{
  if (family)
    {
      int ret;

      /* Count in a single family. */

      if (growing)
        {
          gchar *quoted_family = sql_quote (family);
          gchar *quoted_selector = sql_quote (selector);
          ret = sql_int ("SELECT COUNT(*) FROM nvts WHERE family = '%s';",
                         quoted_family);
          ret -= sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                          " WHERE exclude = 1 AND type = 2"
                          " AND name = '%s' AND family = '%s';",
                          quoted_selector,
                          quoted_family);
          g_free (quoted_family);
          g_free (quoted_selector);
        }
      else
        {
          gchar *quoted_selector = sql_quote (selector);
          gchar *quoted_family = sql_quote (family);
          ret = sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                         " WHERE exclude = 0 AND type = 2"
                         " AND name = '%s' AND family = '%s';",
                         quoted_selector,
                         quoted_family);
          g_free (quoted_family);
          g_free (quoted_selector);
        }

      return ret;
   }
 else
   {
     int count;
     iterator_t families;

     /* Count in each family. */

     count = 0;
     init_family_iterator (&families, 0, NULL, 1);
     while (next (&families))
       {
         const char *name = family_iterator_name (&families);
         if (name)
           count += nvt_selector_nvt_count (selector,
                                            name,
                                            nvt_selector_family_growing
                                             (selector, name, growing));
       }
     cleanup_iterator (&families);

     return count;
   }
}

/**
 * @brief Remove all selectors of a certain family from an NVT selector.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  quoted_family    SQL-quoted family name.
 * @param[in]  type             Selector type to remove.
 */
static void
nvt_selector_remove (const char* quoted_selector,
                     const char* quoted_family,
                     int type)
{
  if (strcmp (quoted_selector, MANAGE_NVT_SELECTOR_UUID_ALL) == 0)
    return;
  if (type == NVT_SELECTOR_TYPE_ANY)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND"
         " ((type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
         "   AND family = '%s')"
         "  OR (type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
         "      AND family_or_nvt = '%s'));",
         quoted_selector,
         quoted_family,
         quoted_family);
  else if (type == NVT_SELECTOR_TYPE_NVT)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
         " AND family = '%s';",
         quoted_selector,
         quoted_family);
  else if (type == NVT_SELECTOR_TYPE_FAMILY)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
         " AND family_or_nvt = '%s';",
         quoted_selector,
         quoted_family);
}

/**
 * @brief Remove all selectors of a certain type from an NVT selector.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  family_or_nvt    SQL-quoted family name or NVT UUID.
 * @param[in]  type             Selector type to remove.
 */
static void
nvt_selector_remove_selector (const char* quoted_selector,
                              const char* family_or_nvt,
                              int type)
{
  if (strcmp (quoted_selector, MANAGE_NVT_SELECTOR_UUID_ALL) == 0)
    return;
  if (type == NVT_SELECTOR_TYPE_ANY)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s' AND family_or_nvt = '%s');",
         quoted_selector,
         family_or_nvt);
  else if (type == NVT_SELECTOR_TYPE_ALL)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL) ";",
         quoted_selector);
  else
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND type = %i"
         " AND family_or_nvt = '%s';",
         quoted_selector,
         type,
         family_or_nvt);
}

/**
 * @brief Add a selector to an NVT selector.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  quoted_family_or_nvt  SQL-quoted family or NVT name.
 * @param[in]  quoted_family    SQL-quoted family name (NULL for families).
 * @param[in]  exclude          1 exclude selector, 0 include selector.
 */
static void
nvt_selector_add (const char* quoted_selector,
                  const char* quoted_family_or_nvt,
                  const char* quoted_family,
                  int exclude)
{
  if (quoted_family == NULL)
    sql ("INSERT INTO nvt_selectors"
         " (name, exclude, type, family_or_nvt, family)"
         " VALUES ('%s', %i, "
         G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
         ", '%s', '%s');",
         quoted_selector,
         exclude,
         quoted_family_or_nvt,
         quoted_family_or_nvt);
  else
    sql ("INSERT INTO nvt_selectors"
         " (name, exclude, type, family_or_nvt, family)"
         " VALUES ('%s', %i, "
         G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
         ", '%s', '%s');",
         quoted_selector,
         exclude,
         quoted_family_or_nvt,
         quoted_family);
}

/**
 * @brief Set the family of an NVT selector.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  family_or_nvt    Family name or NVT OID of selector.
 * @param[in]  type             Selector type to remove.
 * @param[in]  family           New family.
 */
static void
nvt_selector_set_family (const char* quoted_selector,
                         const char* family_or_nvt,
                         int type,
                         const char *family)
{
  gchar *quoted_family_or_nvt, *quoted_family;

  quoted_family_or_nvt = sql_quote (family_or_nvt);
  quoted_family = sql_quote (family);
  sql ("UPDATE nvt_selectors SET family = '%s'"
       " WHERE name = '%s'"
       " AND family_or_nvt = '%s'"
       " AND type = %i;",
       quoted_family,
       quoted_selector,
       quoted_family_or_nvt,
       type);
  g_free (quoted_family);
  g_free (quoted_family_or_nvt);
}

/**
 * @brief Check whether a family is selected.
 *
 * Only works for "generating from empty" selection.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  quoted_family    SQL-quoted family name (NULL for families).
 *
 * @return 1 if selected, else 0.
 */
static int
family_is_selected (const char* quoted_selector, const char* quoted_family)
{
  return sql_int ("SELECT count(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND (type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                  "      AND family = '%s')"
                  " OR (type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                  "     AND family_or_nvt = '%s');",
                  quoted_selector,
                  quoted_family,
                  quoted_family);
}

/**
 * @brief Check whether an NVT selector has a particular selector.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  family_or_nvt    SQL-quoted UUID of NVT, or family name.
 * @param[in]  type             Selector type.
 * @param[in]  exclude          1 exclude, 0 include.
 *
 * @return 1 if contains include/exclude, else 0.
 */
static int
nvt_selector_has (const char* quoted_selector, const char* family_or_nvt,
                  int type, int exclude)
{
  return sql_int ("SELECT count(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND type = %i"
                  " AND exclude = %i"
                  " AND family_or_nvt = '%s'"
                  " LIMIT 1;",
                  quoted_selector,
                  type,
                  exclude,
                  family_or_nvt);
}

/**
 * @brief Starts the SQL transaction for modify_config and finds the config.
 *
 * @param[in]  config_id    UUID of the config to find.
 * @param[out] config_out   Row ID of the config or 0 if not found.
 * 
 * @return 0 success, 1 config not found, -1 error.
 */
int
manage_modify_config_start (const char *config_id, config_t *config_out)
{
  sql_begin_immediate ();
  
  if (find_config_with_permission (config_id, config_out, "modify_config"))
    {
      sql_rollback ();
      return -1;
    }
  if (*config_out == 0)
    {
      sql_rollback ();
      return 1;
    }
  
  return 0;
}

/**
 * @brief Cancels a manage_config command and rolls back the changes.
 */
void
manage_modify_config_cancel ()
{
  sql_rollback ();
}

/**
 * @brief Commits the changes of a manage_config command.
 */
void
manage_modify_config_commit ()
{
  sql_commit ();
}

/**
 * @brief Refresh NVT selection of a config from given families.
 *
 * @param[in]  config                Config to modify.
 * @param[in]  growing_all_families  Growing families with all selection.
 * @param[in]  static_all_families   Static families with all selection.
 * @param[in]  growing_families      The rest of the growing families.
 * @param[in]  grow_families         1 if families should grow, else 0.
 * @param[out] rejected_family       Return of family if one was rejected.
 *
 * @return 0 success, 1 config in use, 2 whole-only families must be growing
 *         and include entire family, -1 error.
 */
int
manage_set_config_families (config_t config,
                            GPtrArray* growing_all_families,
                            GPtrArray* static_all_families,
                            GPtrArray* growing_families,
                            int grow_families,
                            gchar **rejected_family)
{
  static const gchar *wholes[] = FAMILIES_WHOLE_ONLY;
  iterator_t families;
  gchar *quoted_selector;
  int constraining;
  char *selector;

  /* Ensure that whole-only families include all NVTs and are growing. */

  if (rejected_family)
    *rejected_family = NULL;

  for (const gchar **whole = wholes; *whole; whole++)
    {
      if (member (static_all_families, *whole)
          || member (growing_families, *whole))
        {
          if (member (static_all_families, *whole))
            g_debug ("%s rejected static/all whole-only family %s",
                     __func__, *whole);
          else if (member (growing_families, *whole))
            g_debug ("%s rejected growing/empty whole-only family %s",
                     __func__, *whole);

          if (rejected_family)
            *rejected_family = g_strdup (*whole);
          return 2;
        }
    }

  /* Check the args. */

  if (sql_int ("SELECT count(*) FROM tasks"
               " WHERE config = %llu AND hidden = 0;",
               config))
    {
      return 1;
    }

  if (config_type (config) > 0)
    {
      return 0;
    }
  constraining = config_families_growing (config);

  if (constraining + grow_families == 1)
    {
      if (switch_representation (config, constraining))
        {
          return -1;
        }
      constraining = constraining == 0;
    }

  selector = config_nvt_selector (config);
  if (selector == NULL)
    {
      /* The config should always have a selector. */
      return -1;
    }
  quoted_selector = sql_quote (selector);

  /* Loop through all the known families. */

  init_family_iterator (&families, 1, NULL, 1);
  while (next (&families))
    {
      const char *family;

      family = family_iterator_name (&families);
      if (family)
        {
          int old_nvt_count, new_nvt_count = 0, was_selected, max_nvt_count;
          int family_growing;
          int growing_all = member (growing_all_families, family);
          int static_all = member (static_all_families, family);
          gchar *quoted_family = sql_quote (family);

          assert ((growing_all && static_all) == 0);

          family_growing = nvt_selector_family_growing (selector,
                                                        family,
                                                        constraining);

          old_nvt_count
            = nvt_selector_nvt_count (selector, family, family_growing);

          max_nvt_count = family_nvt_count (family);

          if (growing_all || static_all)
            {
              if (old_nvt_count == max_nvt_count
                  && ((growing_all && family_growing)
                      || (static_all && family_growing == 0)))
                {
                  /* Already in required state. */
                  g_free (quoted_family);
                  continue;
                }

              was_selected = family_is_selected (quoted_selector,
                                                 quoted_family);

              /* Flush all selectors in the family from the config. */

              nvt_selector_remove (quoted_selector,
                                   quoted_family,
                                   NVT_SELECTOR_TYPE_ANY);

              if (static_all)
                {
                  iterator_t nvts;

                  /* Static selection of all the NVT's currently in the
                   * family. */

                  if (constraining)
                    {
                      /* Constraining the universe. */

                      /* Add an exclude for the family. */

                      nvt_selector_add (quoted_selector,
                                        quoted_family,
                                        NULL,
                                        1);
                    }
                  else
                    {
                      /* Generating from empty. */
                    }

                  /* Add an include for every NVT in the family. */

                  init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0, family,
                                     NULL, 1, NULL);
                  while (next (&nvts))
                    {
                      nvt_selector_add (quoted_selector,
                                        nvt_iterator_oid (&nvts),
                                        quoted_family,
                                        0);
                      new_nvt_count++;
                    }
                  cleanup_iterator (&nvts);
                }
              else if (growing_all)
                {
                  /* Selection of an entire family, which grows with the family. */

                  if (constraining)
                    {
                      /* Constraining the universe. */
                    }
                  else
                    {
                      /* Generating from empty.  Add an include for the
                       * family. */

                      nvt_selector_add (quoted_selector,
                                        quoted_family,
                                        NULL,
                                        0);

                    }

                  new_nvt_count = max_nvt_count;
                }

              /* Update the cached config info. */

              sql ("UPDATE configs SET nvt_count = nvt_count - %i + %i,"
                   " nvts_growing = %i, family_count = family_count + %i,"
                   " modification_time = m_now ()"
                   " WHERE id = %llu;",
                   old_nvt_count,
                   new_nvt_count,
                   growing_all
                    ? 1
                    /* Recalculate the NVT growing state. */
                    : nvt_selector_nvts_growing_2 (quoted_selector,
                                                   constraining),
                   was_selected ? 0 : 1,
                   config);
            }
          else
            {
              int must_grow = member (growing_families, family);

              if (must_grow)
                {
                  /* The resulting family must be growing.  If currently
                   * growing, leave as is, otherwise switch family to
                   * growing. */

                  if (old_nvt_count == max_nvt_count)
                    {
                      iterator_t nvts;

                      /* All were selected.  Clear selection, ensuring that
                       * the family is growing in the process.  */

                      nvt_selector_remove (quoted_selector,
                                           quoted_family,
                                           NVT_SELECTOR_TYPE_ANY);

                      if (constraining == 0)
                        /* Generating. */
                        nvt_selector_add (quoted_selector,
                                          quoted_family,
                                          NULL,
                                          0);

                      /* Add an exclude for every NVT in the family. */

                      init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0,
                                         family, NULL, 1, NULL);
                      while (next (&nvts))
                        nvt_selector_add (quoted_selector,
                                          nvt_iterator_oid (&nvts),
                                          quoted_family,
                                          1);
                      cleanup_iterator (&nvts);

                      /* Update the cached config info. */

                      sql ("UPDATE configs SET nvt_count = nvt_count - %i,"
                           " nvts_growing = 1, modification_time = m_now ()"
                           " WHERE id = %llu;",
                           old_nvt_count,
                           config);
                    }
                  else if (family_growing == 0)
                    {
                      iterator_t nvts;

                      if (constraining == 0)
                        nvt_selector_add (quoted_selector,
                                          quoted_family,
                                          NULL,
                                          0);

                      /* Remove any included NVT, add excludes for all
                       * other NVT's. */

                      init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0,
                                         family, NULL, 1, NULL);
                      while (next (&nvts))
                        if (nvt_selector_has (quoted_selector,
                                              nvt_iterator_oid (&nvts),
                                              NVT_SELECTOR_TYPE_NVT,
                                              0))
                          nvt_selector_remove_selector
                           (quoted_selector,
                            nvt_iterator_oid (&nvts),
                            NVT_SELECTOR_TYPE_NVT);
                        else
                          nvt_selector_add (quoted_selector,
                                            nvt_iterator_oid (&nvts),
                                            quoted_family,
                                            1);
                      cleanup_iterator (&nvts);

                      /* Update the cached config info. */

                      sql ("UPDATE configs SET nvts_growing = 1,"
                           " modification_time = m_now ()"
                           " WHERE id = %llu;",
                           config);
                    }
                }
              else
                {
                  /* The resulting family must be static.  If currently
                   * static, leave as is, otherwise switch family to
                   * static. */

                  if (old_nvt_count == max_nvt_count)
                    {
                      /* All were selected, clear selection, ensuring the
                       * family is static in the process. */

                      nvt_selector_remove (quoted_selector,
                                           quoted_family,
                                           NVT_SELECTOR_TYPE_ANY);
                      if (constraining)
                        nvt_selector_add (quoted_selector,
                                          quoted_family,
                                          NULL,
                                          1);

                      /* Update the cached config info. */

                      sql ("UPDATE configs SET nvts_growing = %i,"
                           " nvt_count = nvt_count - %i,"
                           " family_count = family_count - 1,"
                           " modification_time = m_now ()"
                           " WHERE id = %llu;",
                           /* Recalculate the NVT growing state. */
                           nvt_selector_nvts_growing_2 (quoted_selector,
                                                        constraining),
                           old_nvt_count,
                           config);
                    }
                  else if (family_growing)
                    {
                      iterator_t nvts;

                      if (constraining)
                        nvt_selector_add (quoted_selector,
                                          quoted_family,
                                          NULL,
                                          1);
                      else
                        nvt_selector_remove (quoted_selector,
                                             quoted_family,
                                             NVT_SELECTOR_TYPE_FAMILY);

                      /* Remove any excluded NVT; add includes for all
                       * other NVT's. */

                      init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0,
                                         family, NULL, 1, NULL);
                      while (next (&nvts))
                        if (nvt_selector_has (quoted_selector,
                                              nvt_iterator_oid (&nvts),
                                              NVT_SELECTOR_TYPE_NVT,
                                              1))
                          nvt_selector_remove_selector
                            (quoted_selector,
                             nvt_iterator_oid (&nvts),
                             NVT_SELECTOR_TYPE_NVT);
                        else
                          nvt_selector_add (quoted_selector,
                                            nvt_iterator_oid (&nvts),
                                            quoted_family,
                                            0);
                      cleanup_iterator (&nvts);

                      /* Update the cached config info. */

                      sql ("UPDATE configs SET nvts_growing = %i,"
                           " modification_time = m_now ()"
                           " WHERE id = %llu;",
                           /* Recalculate the NVT growing state. */
                           nvt_selector_nvts_growing_2 (quoted_selector,
                                                        constraining),
                           config);
                    }
                }
            }

          g_free (quoted_family);
        }
    }
  cleanup_iterator (&families);

  g_free (quoted_selector);
  free (selector);
  return 0;
}

/**
 * @brief Insert NVT selectors.
 *
 * @param[in]  quoted_name   Name of NVT selector.
 * @param[in]  selectors     NVT selectors.
 * @param[in]  allow_errors  Whether certain errors are allowed.
 *
 * @return 0 success, -1 error, -3 input error.
 */
static int
insert_nvt_selectors (const char *quoted_name,
                      const array_t* selectors, /* nvt_selector_t. */
                      int allow_errors)
{
  int index = 0;
  const nvt_selector_t *selector;
  if (selectors == NULL) return -3;
  while ((selector = (nvt_selector_t*) g_ptr_array_index (selectors, index++)))
    {
      int type;

      if (selector->type == NULL) return -3;

      /** @todo Check that selector->type is actually an integer. */
      type = atoi (selector->type);

      if ((selector->family_or_nvt != NULL)
          && (type == NVT_SELECTOR_TYPE_NVT))
        {
          gchar *quoted_family_or_nvt, *quoted_family, *family = NULL;

          /* An NVT selector. */

          family = nvt_family (selector->family_or_nvt);
          if (family == NULL)
            g_debug ("%s: NVT '%s' in config '%s' does not have a family",
                     __func__,
                     selector->family_or_nvt,
                     quoted_name);

          quoted_family_or_nvt = sql_quote (selector->family_or_nvt);
          quoted_family = sql_quote (family ? family : "");
          sql ("INSERT into nvt_selectors (name, exclude, type, family_or_nvt,"
               " family)"
               " VALUES ('%s', %i, %i, '%s', '%s');",
               quoted_name,
               selector->include ? 0 : 1,
               type,
               quoted_family_or_nvt,
               quoted_family);
          g_free (quoted_family_or_nvt);
          g_free (quoted_family);
        }
      else if (selector->family_or_nvt)
        {
          gchar *quoted_family_or_nvt;

          /* A family selector. */

          if (type != NVT_SELECTOR_TYPE_FAMILY)
            {
              g_warning ("%s: skipping NVT '%s' from import of config '%s'"
                         " because the type is wrong (expected family)",
                         __func__,
                         selector->family_or_nvt,
                         quoted_name);
              if (allow_errors)
                continue;
              return -1;
            }

          quoted_family_or_nvt = sql_quote (selector->family_or_nvt);

          sql ("INSERT into nvt_selectors (name, exclude, type, family_or_nvt,"
               " family)"
               " VALUES ('%s', %i, %i, '%s', '%s');",
               quoted_name,
               selector->include ? 0 : 1,
               type,
               quoted_family_or_nvt,
               quoted_family_or_nvt);
          g_free (quoted_family_or_nvt);
        }
      else
        {
          /* An "all" selector. */

          if (type != NVT_SELECTOR_TYPE_ALL)
            {
              g_warning ("%s: skipping NVT from import of config '%s'"
                         " because the type is wrong (expected all)",
                         __func__,
                         quoted_name);
              if (allow_errors)
                continue;
              return -1;
            }

          sql ("INSERT into nvt_selectors (name, exclude, type, family_or_nvt,"
               " family)"
               " VALUES ('%s', %i, %i, NULL, NULL);",
               quoted_name,
               selector->include ? 0 : 1,
               type);
        }
    }
  return 0;
}

/**
 * @brief Change the family of an NVT in a config.
 *
 * @param[in]  config      Config.
 * @param[in]  oid         NVT OID.
 * @param[in]  old_family  Name of old family.
 * @param[in]  new_family  Name of new family.
 *
 * @return 0 success, -1 error.
 */
static int
config_update_nvt_family (resource_t config, const char *oid,
                          const char *old_family, const char *new_family)
{
  int constraining;
  char* selector;
  gchar *quoted_selector;

  selector = config_nvt_selector (config);
  if (selector == NULL)
    {
      g_warning ("%s: Failed to get config selector", __func__);
      return -1;
    }
  quoted_selector = sql_quote (selector);

  constraining = config_families_growing (config);

  g_debug ("%s: Updating NVT family for selector '%s'", __func__, selector);

  if (constraining)
    {
      /* Constraining the universe. */

      g_debug ("%s:   Selector constrains universe", __func__);

      if (nvt_selector_family_growing (selector, old_family, constraining))
        {
          /* Old family is growing. */

          g_debug ("%s:   Old family is growing", __func__);

          if (nvt_selector_has (quoted_selector, oid, NVT_SELECTOR_TYPE_NVT,
                                0 /* Included. */))
            {
              /* NVT explicitly included in old family, which is redundant, so
               * drop selector. */
              g_debug ("%s:   Drop selector", __func__);
              nvt_selector_remove_selector (quoted_selector,
                                            oid,
                                            NVT_SELECTOR_TYPE_NVT);
            }
          else if (nvt_selector_has (quoted_selector, oid,
                                     NVT_SELECTOR_TYPE_NVT,
                                     1 /* Excluded. */))
            {
              /* NVT explicitly excluded from old family. */

              g_debug ("%s:   NVT excluded from old family", __func__);

              if (nvt_selector_family_growing (selector, new_family,
                                               constraining))
                {
                  /* New family is growing, change NVT to new family. */
                  g_debug ("%s:   Change family", __func__);
                  nvt_selector_set_family (quoted_selector,
                                           oid,
                                           NVT_SELECTOR_TYPE_NVT,
                                           new_family);
                }
              else
                {
                  /* New family static, NVT excluded already, so drop NVT
                   * selector. */
                  g_debug ("%s:   Remove selector", __func__);
                  nvt_selector_remove_selector (quoted_selector,
                                                oid,
                                                NVT_SELECTOR_TYPE_NVT);
                }
            }
        }
      else
        {
          /* Old family is static. */

          g_debug ("%s:   Old family is static", __func__);

          if (nvt_selector_has (quoted_selector, oid, NVT_SELECTOR_TYPE_NVT,
                                0 /* Included. */))
            {
              /* NVT explicitly included in old family. */

              g_debug ("%s:   NVT included in old family", __func__);

              if (nvt_selector_family_growing (selector, new_family,
                                               constraining))
                {
                  /* New family is growing so it already includes the NVT.
                   * Remove the NVT selector. */
                  g_debug ("%s:   Remove selector", __func__);
                  nvt_selector_remove_selector (quoted_selector,
                                                oid,
                                                NVT_SELECTOR_TYPE_NVT);
                }
              else
                {
                  /* New family static, change NVT to new family. */
                  g_debug ("%s:   Change family", __func__);
                  nvt_selector_set_family (quoted_selector,
                                           oid,
                                           NVT_SELECTOR_TYPE_NVT,
                                           new_family);
                }
            }
          else if (nvt_selector_has (quoted_selector, oid,
                                     NVT_SELECTOR_TYPE_NVT,
                                     1 /* Excluded. */))
            {
              /* NVT explicitly excluded from old family, which is redundant, so
               * remove NVT selector. */
              g_debug ("%s:   Remove selector", __func__);
              nvt_selector_remove_selector (quoted_selector,
                                            oid,
                                            NVT_SELECTOR_TYPE_NVT);
            }
        }
    }
  else
    {
      /* Generating from empty. */

      g_debug ("%s:   Selector generates from empty", __func__);

      if (nvt_selector_family_growing (selector, old_family, constraining))
        {
          /* Old family is growing. */

          g_debug ("%s:   Old family is growing", __func__);

          if (nvt_selector_has (quoted_selector, oid, NVT_SELECTOR_TYPE_NVT,
                                0 /* Included. */))
            {
              /* NVT explicitly included in old family.  This is redundant, so
               * just remove the NVT selector. */
              g_debug ("%s:   Remove selector", __func__);
              nvt_selector_remove_selector (quoted_selector,
                                            oid,
                                            NVT_SELECTOR_TYPE_NVT);
            }
          else if (nvt_selector_has (quoted_selector, oid,
                                     NVT_SELECTOR_TYPE_NVT,
                                     1 /* Excluded. */))
            {
              /* NVT explicitly excluded from old family. */

              g_debug ("%s:   NVT excluded from old family", __func__);

              if (nvt_selector_family_growing (selector, new_family,
                                               constraining))
                {
                  /* New family is growing, change NVT to new family. */
                  g_debug ("%s:   Change family", __func__);
                  nvt_selector_set_family (quoted_selector,
                                           oid,
                                           NVT_SELECTOR_TYPE_NVT,
                                           new_family);
                }
              else
                {
                  /* New family static, so the NVT is already excluded from the
                   * new family.  Remove the NVT selector. */
                  g_debug ("%s:   Remove selector", __func__);
                  nvt_selector_remove_selector (quoted_selector,
                                                oid,
                                                NVT_SELECTOR_TYPE_NVT);
                }
            }
        }
      else
        {
          /* Old family is static. */

          g_debug ("%s:   Old family is static", __func__);

          if (nvt_selector_has (quoted_selector, oid, NVT_SELECTOR_TYPE_NVT,
                                0 /* Included. */))
            {
              /* NVT explicitly included in old family. */

              g_debug ("%s:   NVT included in old family", __func__);

              if (nvt_selector_family_growing (selector, new_family,
                                               constraining))
                {
                  /* New family growing, so the NVT is already in there.  Remove
                   * the NVT selector. */
                  g_debug ("%s:   Remove selector", __func__);
                  nvt_selector_remove_selector (quoted_selector,
                                                oid,
                                                NVT_SELECTOR_TYPE_NVT);
                }
              else
                {
                  /* New family is static, change NVT to new family. */
                  g_debug ("%s:   Change family", __func__);
                  nvt_selector_set_family (quoted_selector,
                                           oid,
                                           NVT_SELECTOR_TYPE_NVT,
                                           new_family);
                }
            }
          else if (nvt_selector_has (quoted_selector, oid,
                                     NVT_SELECTOR_TYPE_NVT,
                                     1 /* Excluded. */))
            {
              /* NVT explicitly excluded from old family.  This is redundant,
               * so just remove the NVT selector. */
              g_debug ("%s:   NVT exclude from old family, remove selector",
                       __func__);
              nvt_selector_remove_selector (quoted_selector,
                                            oid,
                                            NVT_SELECTOR_TYPE_NVT);
            }
        }
    }

  g_free (quoted_selector);
  free (selector);
  return 0;
}

/**
 * @brief Change the family of an NVT in all configs.
 *
 * @param[in]  oid         NVT OID.
 * @param[in]  old_family  Name of old family.
 * @param[in]  new_family  Name of new family.
 *
 * @return 0 success, -1 error.
 */
static int
update_nvt_family (const char *oid, const char *old_family,
                   const char *new_family)
{
  int ret;
  iterator_t rows;

  ret = 0;
  init_iterator (&rows, "SELECT id FROM configs WHERE type = 0;");
  while (next (&rows))
    if (config_update_nvt_family (iterator_int64 (&rows, 0), oid, old_family,
                                  new_family))
      ret = -1;
  cleanup_iterator (&rows);
  return ret;
}

/**
 * @brief Ensure that all configs refer to the right NVT families.
 *
 * When the family of an NVT is changed in the feed, then the config
 * refers to the wrong family.
 *
 * @return 0 success, -1 error.
 */
int
check_config_families ()
{
  int ret;
  iterator_t selectors;

  ret = 0;
  /* Get all NVT selectors that have the wrong family. */
  init_iterator (&selectors,
                 "SELECT DISTINCT family_or_nvt, family,"
                 "       (SELECT family FROM nvts WHERE oid = family_or_nvt)"
                 " FROM nvt_selectors"
                 " WHERE type = 2"
                 " AND family != (SELECT family FROM nvts"
                 "                WHERE oid = family_or_nvt);");
  while (next (&selectors))
    /* Update the family of the NVT selector. */
    if (update_nvt_family (iterator_string (&selectors, 0),
                           iterator_string (&selectors, 1),
                           iterator_string (&selectors, 2)))
      ret = -1;
  cleanup_iterator (&selectors);
  return ret;
}


/* NVT preferences.  This is part of Configs. */

/**
 * @brief Add/replace an NVT preference.
 *
 * @param[in]  name    The name of the preference.
 * @param[in]  value   The value of the preference.
 */
void
manage_nvt_preference_add (const char* name, const char* value)
{
  gchar* quoted_name = sql_quote (name);
  gchar* quoted_value = sql_quote (value);

  if (strcmp (name, "port_range"))
    {
      if (sql_int ("SELECT EXISTS"
                   "  (SELECT * FROM nvt_preferences"
                   "   WHERE name = '%s')",
                   quoted_name))
        sql ("DELETE FROM nvt_preferences WHERE name = '%s';", quoted_name);

      sql ("INSERT into nvt_preferences (name, value)"
           " VALUES ('%s', '%s');",
           quoted_name, quoted_value);
    }

  g_free (quoted_name);
  g_free (quoted_value);
}

/**
 * @brief Initialise an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  oid       OID of NVT, NULL for all preferences.
 */
void
init_nvt_preference_iterator (iterator_t* iterator, const char *oid)
{
  if (oid)
    {
      gchar *quoted_oid = sql_quote (oid);
      init_iterator (iterator,
                     "SELECT name, value FROM nvt_preferences"
                     " WHERE name %s '%s:%%'"
                     " AND name != 'cache_folder'"
                     " AND name != 'include_folders'"
                     " AND name != 'nasl_no_signature_check'"
                     " AND name != 'network_targets'"
                     " AND name != 'ntp_save_sessions'"
                     " AND name != '%s:0:entry:Timeout'"
                     " AND name NOT %s 'server_info_%%'"
                     /* Task preferences. */
                     " AND name != 'max_checks'"
                     " AND name != 'max_hosts'"
                     " ORDER BY name ASC",
                     sql_ilike_op (),
                     quoted_oid,
                     quoted_oid,
                     sql_ilike_op ());
      g_free (quoted_oid);
    }
  else
    init_iterator (iterator,
                   "SELECT name, value FROM nvt_preferences"
                   " WHERE name != 'cache_folder'"
                   " AND name != 'include_folders'"
                   " AND name != 'nasl_no_signature_check'"
                   " AND name != 'network_targets'"
                   " AND name != 'ntp_save_sessions'"
                   " AND name NOT %s '%%:0:entry:Timeout'"
                   " AND name NOT %s 'server_info_%%'"
                   /* Task preferences. */
                   " AND name != 'max_checks'"
                   " AND name != 'max_hosts'"
                   " ORDER BY name ASC",
                   sql_ilike_op (),
                   sql_ilike_op ());
}

/**
 * @brief Get the name from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_preference_iterator_name, 0);

/**
 * @brief Get the value from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_preference_iterator_value, 1);

/**
 * @brief Get the real name from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Real name.
 */
char*
nvt_preference_iterator_real_name (iterator_t* iterator)
{
  const char *ret;
  char *real_name = NULL;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 0);
  if (ret)
    {
      char **splits = g_strsplit (ret, ":", 4);
      if (splits && g_strv_length (splits) == 4)
        real_name = g_strdup (splits[3]);
      g_strfreev (splits);
      return real_name ?: g_strdup (ret);
    }
  return NULL;
}

/**
 * @brief Get the type from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type.
 */
char*
nvt_preference_iterator_type (iterator_t* iterator)
{
  const char *ret;
  char *type = NULL;
  if (iterator->done)
    return NULL;
  ret = iterator_string (iterator, 0);
  if (ret)
    {
      char **splits = g_strsplit (ret, ":", 4);
      if (splits && g_strv_length (splits) == 4)
        type = g_strdup (splits[2]);
      g_strfreev (splits);
    }
  return type;
}

/**
 * @brief Get the NVT from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT.
 */
char*
nvt_preference_iterator_oid (iterator_t* iterator)
{
  const char *ret;
  char *oid = NULL;
  if (iterator->done)
    return NULL;
  ret = iterator_string (iterator, 0);
  if (ret)
    {
      char **splits = g_strsplit (ret, ":", 4);
      if (splits && g_strv_length (splits) == 4)
        oid = g_strdup (splits[0]);
      g_strfreev (splits);
    }
  return oid;
}

/**
 * @brief Get the ID from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT.
 */
char*
nvt_preference_iterator_id (iterator_t* iterator)
{
  const char *ret;
  char *id = NULL;

  if (iterator->done)
    return NULL;
  ret = iterator_string (iterator, 0);
  if (ret)
    {
      char **splits = g_strsplit (ret, ":", 4);
      if (splits && g_strv_length (splits) == 4)
        id = g_strdup (splits[1]);
      g_strfreev (splits);
    }
  return id;
}

/**
 * @brief Get the config value from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  config    Config.
 *
 * @return Freshly allocated config value.
 */
char*
nvt_preference_iterator_config_value (iterator_t* iterator, config_t config)
{
  gchar *quoted_name, *value;
  const char *ret;
  if (iterator->done) return NULL;

  quoted_name = sql_quote (iterator_string (iterator, 0));
  value = sql_string ("SELECT value FROM config_preferences"
                      " WHERE config = %llu"
                      " AND name = '%s'"
                      /* Ensure that the NVT pref comes first, in case an
                       * error in the GSA added the NVT pref as a Scanner
                       * pref. */
                      " ORDER BY type",
                      config,
                      quoted_name);
  g_free (quoted_name);
  if (value) return value;

  ret = iterator_string (iterator, 1);
  if (ret) return g_strdup (ret);
  return NULL;
}

/**
 * @brief Get the number preferences available for an NVT.
 *
 * @param[in]  oid  OID of NVT.
 *
 * @return Number of possible preferences on NVT.
 */
int
nvt_preference_count (const char *oid)
{
  gchar *quoted_oid = sql_quote (oid);
  int ret = sql_int ("SELECT COUNT(*) FROM nvt_preferences"
                     " WHERE name != '%s:0:entry:Timeout'"
                     "   AND name %s '%s:%%';",
                     quoted_oid,
                     sql_ilike_op (),
                     quoted_oid);
  g_free (quoted_oid);
  return ret;
}

/**
 * @brief Get the value of a task preference.
 *
 * @param[in]  task  Task.
 * @param[in]  name  Preference name.
 *
 * @return Freshly allocated task preference value or NULL if pref missing.
 */
char*
task_preference_value (task_t task, const char *name)
{
  gchar *quoted_name, *value;

  quoted_name = sql_quote (name);
  value = sql_string ("SELECT value FROM task_preferences"
                      " WHERE task = %llu"
                      " AND name = '%s';",
                      task,
                      quoted_name);
  if (value)
    {
      g_free (quoted_name);
      return value;
    }

  value = sql_string ("SELECT value FROM nvt_preferences"
                      " WHERE name = '%s';",
                      quoted_name);
  g_free (quoted_name);
  return value;
}

/**
 * @brief Set the preferences of a task.
 *
 * Only the given preferences are affected.  A NULL value means to remove
 * the preference (reverts to using scanner value).
 *
 * @param[in]  task         Task.
 * @param[in]  preferences  Preferences.
 *
 * @return 0 success, 1 invalid auto_delete value, 2 auto_delete_data out of
 *         range.
 */
int
set_task_preferences (task_t task, array_t *preferences)
{
  if (preferences)
    {
      guint index;
      for (index = 0; index < preferences->len; index++)
        {
          name_value_t *pair;
          pair = (name_value_t*) g_ptr_array_index (preferences, index);
          if (pair && pair->name)
            {
              gchar *quoted_name;
              quoted_name = sql_quote (pair->name);
              if (pair->value)
                {
                  gchar *quoted_value;

                  if ((strcmp (pair->name, "auto_delete") == 0)
                      && (strcmp (pair->value, "keep"))
                      && (strcmp (pair->value, "no")))
                    {
                      return 1;
                    }

                  if (strcmp (pair->name, "auto_delete_data") == 0)
                    {
                      int keep;
                      keep = atoi (pair->value);
                      if (keep < AUTO_DELETE_KEEP_MIN
                          || keep > AUTO_DELETE_KEEP_MAX)
                        return 2;
                    }

                  if ((strcmp (pair->name, "in_assets") == 0)
                      && scanner_type (task_scanner (task)) == SCANNER_TYPE_CVE)
                    quoted_value = g_strdup ("no");
                  else
                    quoted_value = sql_quote (pair->value);
                  sql_begin_immediate ();
                  if (sql_int ("SELECT COUNT(*) FROM task_preferences"
                               " WHERE task = %llu AND name = '%s';",
                               task,
                               quoted_name))
                    sql ("UPDATE task_preferences"
                         " SET value = '%s'"
                         " WHERE task = %llu AND name = '%s';",
                         quoted_value,
                         task,
                         quoted_name);
                  else
                    sql ("INSERT INTO task_preferences"
                         " (task, name, value)"
                         " VALUES"
                         " (%llu, '%s', '%s');",
                         task,
                         quoted_name,
                         quoted_value);
                  sql_commit ();
                  g_free (quoted_value);
                }
              else
                sql ("DELETE FROM task_preferences"
                     " WHERE task = %llu AND name = '%s';",
                     task, quoted_name);
              g_free (quoted_name);
              sql ("UPDATE tasks SET modification_time = m_now ()"
                   " WHERE id = %llu;",
                   task);
            }
        }
    }
  return 0;
}


/* Configs. */

/**
 * @brief Find a config for a set of permissions, given a UUID.
 *
 * @param[in]   uuid        UUID of config.
 * @param[out]  config      Config return, 0 if successfully failed to find
 *                          config.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find config), TRUE on error.
 */
gboolean
find_config_with_permission (const char* uuid, config_t* config,
                             const char *permission)
{
  return find_resource_with_permission ("config", uuid, config, permission, 0);
}

/**
 * @brief Find a config given a UUID.
 *
 * This does not do any permission checks.
 *
 * @param[in]   uuid     UUID of resource.
 * @param[out]  config   Config return, 0 if no such config.
 *
 * @return FALSE on success (including if no such config), TRUE on error.
 */
gboolean
find_config_no_acl (const char *uuid, config_t *config)
{
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  switch (sql_int64 (config,
                     "SELECT id FROM configs WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *config = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Find a trash config given a UUID.
 *
 * This does not do any permission checks.
 *
 * @param[in]   uuid     UUID of resource.
 * @param[out]  config   Config return, 0 if no such config.
 *
 * @return FALSE on success (including if no such config), TRUE on error.
 */
gboolean
find_trash_config_no_acl (const char *uuid, config_t *config)
{
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  switch (sql_int64 (config,
                     "SELECT id FROM configs_trash WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *config = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Gets an NVT preference by id or by name.
 *
 * Note: This currently only gets the fields needed by create_config.
 *
 * @param[in]  nvt_oid    OID of the NVT the preference belongs to.
 * @param[in]  find_id    Preference id to find, or NULL.
 * @param[in]  check_name Preference name to check.
 * @param[in]  check_type Preference name to check.
 * @param[in]  value      Value to assign to the preference.
 *
 * @return Newly allocated preference, freed with preference_free,
 *          or NULL (on error or if not found).
 */
preference_t *
get_nvt_preference_by_id (const char *nvt_oid,
                          const char *find_id,
                          const char *check_name,
                          const char *check_type,
                          const char *value)
{
  preference_t *new_pref;
  char *full_name, *id, *name, *type, *nvt_name, *default_value, *hr_name;
  array_t *alts;
  gchar *quoted_oid, *quoted_id;

  full_name = name = type = nvt_name = default_value = hr_name = NULL;

  /* Check parameters */
  if (nvt_oid == NULL)
    {
      g_warning ("%s: Missing nvt_oid", __func__);
      return NULL;
    }
  if (find_id == NULL || strcmp (find_id, "") == 0)
    {
      g_warning ("%s: Missing or empty find_id", __func__);
      return NULL;
    }
  if (value == NULL)
    {
      g_warning ("%s: Missing value", __func__);
      return NULL;
    }

  /* Try to get by id first */
  quoted_oid = sql_quote (nvt_oid);
  quoted_id = find_id ? sql_quote (find_id) : NULL;

  full_name = sql_string ("SELECT name FROM nvt_preferences"
                          " WHERE name LIKE '%s:%s:%%:%%'",
                          quoted_oid,
                          quoted_id);

  g_free (quoted_oid);
  g_free (quoted_id);

  if (full_name == NULL)
    {
      if (check_name == NULL || strcmp (check_name, "") == 0)
        {
          g_warning ("%s: Preference not found and given name is missing/empty",
                     __func__);
          return NULL;
        }
      if (check_type == NULL || strcmp (check_type, "") == 0)
        {
          g_warning ("%s: Preference not found and given name is missing/empty",
                     __func__);
          return NULL;
        }
      id = strdup (find_id);
      type = strdup (check_type);
      name = strdup (check_name);
    }
  else
    {
      char **full_name_split;

      /* Try to get components of the full name */
      full_name_split = g_strsplit (full_name, ":", 4);

      if (g_strv_length (full_name_split) != 4)
        {
          g_warning ("%s: Preference name %s does not have 4 parts",
                     __func__, full_name);
          g_strfreev (full_name_split);
          free (full_name);
          return NULL;
        }
      free (full_name);

      id = strdup (full_name_split[1]);
      type = strdup (full_name_split[2]);
      name = strdup (full_name_split[3]);
      g_strfreev (full_name_split);

      if (check_type && strcmp (check_type, "") && strcmp (check_type, type))
        g_warning ("%s: type of preference %s:%s (%s) has changed from %s to %s.",
                   __func__, nvt_oid, find_id, name, check_type, type);

      if (check_name && strcmp (check_name, "") && strcmp (check_name, name))
        g_message ("%s: name of preference %s:%s has changed from '%s' to '%s'.",
                   __func__, nvt_oid, find_id, check_name, name);
    }

  alts = make_array ();
  array_terminate (alts);

  new_pref = preference_new (id,
                             name,
                             type,
                             strdup (value),
                             nvt_name,
                             strdup (nvt_oid),
                             alts,
                             default_value,
                             hr_name,
                             1);

  return new_pref;
}

/**
 * @brief Insert preferences into a config.
 *
 * @param[in]  config       Config.
 * @param[in]  preferences  Preferences.
 * @param[in]  config_type  Config type.
 *
 * @return 0 success, -1 error, -4 input error.
 */
static int
config_insert_preferences (config_t config,
                           const array_t* preferences /* preference_t. */,
                           const char* config_type)
{
  int index = 0;
  const preference_t *preference;
  if (preferences == NULL) return -4;
  while ((preference = (preference_t*) g_ptr_array_index (preferences, index++)))
    /* Simply skip the preference if the value is NULL, for exports
     * where sensitive information is left out. */
    if (preference->value)
      {
        GString *value;
        int alt_index = 0;
        const gchar *alt;
        gchar *quoted_value;

        if (preference->name == NULL) return -4;
        if (strcmp (preference->name, "Timeout") == 0)
          {
            gchar *quoted_nvt_oid;

            /* Special Timeout preference. */

            if (preference->nvt_oid == NULL
                && (config_type == NULL || strcmp (config_type, "0") == 0))
              return -4;

            quoted_nvt_oid = sql_quote (preference->nvt_oid);
            quoted_value = sql_quote (preference->value);

            sql ("INSERT into config_preferences (config, type, name, value)"
                 " VALUES (%llu, 'SERVER_PREFS', 'timeout.%s', '%s');",
                 config,
                 quoted_nvt_oid,
                 quoted_value);

            g_free (quoted_nvt_oid);
            g_free (quoted_value);
          }
        else if (preference->type)
          {
            gchar *quoted_type, *quoted_nvt_oid, *quoted_preference_name;
            gchar *quoted_default, *quoted_preference_hr_name;
            gchar *quoted_preference_id;

            /* Presume NVT or OSP preference. */

            if (preference->nvt_oid == NULL
                && (config_type == NULL || strcmp (config_type, "0") == 0))
              return -4;

            value = g_string_new (preference->value);
            while ((alt = (gchar*) g_ptr_array_index (preference->alts,
                                                      alt_index++)))
              {
                g_string_append_printf (value, ";%s", alt);
              }

            quoted_nvt_oid = sql_quote (preference->nvt_oid ?: "");
            quoted_preference_id = sql_quote (preference->id ?: "");
            quoted_preference_name = sql_quote (preference->name);
            quoted_preference_hr_name
              = preference->hr_name
                  ? sql_quote (preference->hr_name)
                  : NULL;
            quoted_type
              = g_str_has_prefix (preference->type, "osp_")
                  ? sql_quote (preference->type + strlen ("osp_"))
                  : sql_quote (preference->type);
            quoted_value = sql_quote (value->str);
            g_string_free (value, TRUE);
            quoted_default = preference->default_value
                              ? sql_quote (preference->default_value)
                              : NULL;

            if (config_type == NULL || strcmp (config_type, "0") == 0)
              {
                /* NVT preference */
                /* OID:PrefID:PrefType:PrefName value */
                sql ("INSERT INTO config_preferences"
                     " (config, type, name, value)"
                     " VALUES (%llu, 'PLUGINS_PREFS', '%s:%s:%s:%s', '%s');",
                     config,
                     quoted_nvt_oid,
                     quoted_preference_id,
                     quoted_type,
                     quoted_preference_name,
                     quoted_value);
              }
            else
              {
                /* OSP preference */
                sql ("INSERT into config_preferences"
                     " (config, type, name, value, default_value, hr_name)"
                     " VALUES (%llu, '%s', '%s', '%s', '%s', '%s');",
                     config,
                     quoted_type,
                     quoted_preference_name,
                     quoted_value,
                     quoted_default,
                     quoted_preference_hr_name
                      ? quoted_preference_name : quoted_preference_hr_name);
              }
            g_free (quoted_nvt_oid);
            g_free (quoted_preference_name);
            g_free (quoted_type);
            g_free (quoted_value);
            g_free (quoted_default);
            g_free (quoted_preference_hr_name);
            g_free (quoted_preference_id);
          }
        else
          {
            gchar *quoted_name;

            /* Presume scanner preference. */

            quoted_name = sql_quote (preference->name);
            quoted_value = sql_quote (preference->value);
            sql ("INSERT into config_preferences (config, type, name, value)"
                 " VALUES (%llu, 'SERVER_PREFS', '%s', '%s');",
                 config,
                 quoted_name,
                 quoted_value);
            g_free (quoted_name);
            g_free (quoted_value);
          }
      }
  return 0;
}

/**
 * @brief Create a config.
 *
 * If a config with the same name exists already then add a unique integer
 * suffix onto the name.
 *
 * @param[in]   check_access   Whether to check for create_config permission.
 * @param[in]   config_id      ID if one is required, else NULL.
 * @param[in]   proposed_name  Proposed name of config.
 * @param[in]   make_name_unique  Whether to make name unique.
 * @param[in]   comment        Comment on config.
 * @param[in]   all_selector   Whether to use "all" selector instead of selectors.
 * @param[in]   selectors      NVT selectors.
 * @param[in]   preferences    Preferences.
 * @param[in]   config_type    Config type.
 * @param[in]   usage_type     The usage type ("scan" or "policy")
 * @param[in]   allow_errors   Whether certain errors are allowed.
 * @param[in]   predefined     Whether config is predefined.
 * @param[out]  config         On success the config.
 * @param[out]  name           On success the name of the config.
 *
 * @return 0 success, 1 config exists already, 99 permission denied, -1 error,
 *         -2 name empty, -3 input error in selectors, -4 input error in
 *         preferences, -5 error in config_id.
 */
static int
create_config_internal (int check_access, const char *config_id,
                        const char *proposed_name,
                        int make_name_unique, const char *comment,
                        int all_selector,
                        const array_t *selectors /* nvt_selector_t. */,
                        const array_t *preferences /* preference_t. */,
                        const char *config_type, const char *usage_type,
                        int allow_errors, int predefined, config_t *config,
                        char **name)
{
  int ret;
  gchar *quoted_comment, *candidate_name, *quoted_candidate_name;
  gchar *quoted_type;
  const char *actual_usage_type;
  char *selector_uuid;
  unsigned int num = 1;

  assert (current_credentials.uuid);

  if (config_id
      && (g_regex_match_simple ("^[-0123456789abcdef]{36}$",
                                config_id, 0, 0)
          == FALSE))
    return -5;

  if (proposed_name == NULL || strlen (proposed_name) == 0) return -2;

  if (all_selector)
    selector_uuid = NULL;
  else
    {
      selector_uuid = gvm_uuid_make ();
      if (selector_uuid == NULL)
        return -1;
    }

  sql_begin_immediate ();

  if (check_access && (acl_user_may ("create_config") == 0))
    {
      sql_rollback ();
      free (selector_uuid);
      return 99;
    }

  candidate_name = g_strdup (proposed_name);
  quoted_candidate_name = sql_quote (candidate_name);
  quoted_type = config_type ? sql_quote (config_type) : g_strdup ("0");
  if (usage_type && strcasecmp (usage_type, "policy") == 0)
    actual_usage_type = "policy";
  else
    actual_usage_type = "scan";

  while (make_name_unique)
    {
      if (!resource_with_name_exists (quoted_candidate_name, "config", 0))
        break;
      g_free (candidate_name);
      g_free (quoted_candidate_name);
      candidate_name = g_strdup_printf ("%s %u", proposed_name, ++num);
      quoted_candidate_name = sql_quote (candidate_name);
    }

  if (comment)
    {
      quoted_comment = sql_nquote (comment, strlen (comment));
      sql ("INSERT INTO configs (uuid, name, owner, nvt_selector, comment,"
           " type, creation_time, modification_time, usage_type, predefined)"
           " VALUES (%s%s%s, '%s',"
           " (SELECT id FROM users WHERE users.uuid = '%s'),"
           " '%s', '%s', '%s', m_now (), m_now (), '%s', %i);",
           config_id ? "'" : "",
           config_id ? config_id : "make_uuid ()",
           config_id ? "'" : "",
           quoted_candidate_name,
           current_credentials.uuid,
           selector_uuid ? selector_uuid : MANAGE_NVT_SELECTOR_UUID_ALL,
           quoted_comment,
           quoted_type,
           actual_usage_type,
           predefined);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO configs (uuid, name, owner, nvt_selector, comment,"
         " type, creation_time, modification_time, usage_type, predefined)"
         " VALUES (%s%s%s, '%s',"
         " (SELECT id FROM users WHERE users.uuid = '%s'),"
         " '%s', '', '%s', m_now (), m_now (), '%s', %i);",
         config_id ? "'" : "",
         config_id ? config_id : "make_uuid ()",
         config_id ? "'" : "",
         quoted_candidate_name,
         current_credentials.uuid,
         selector_uuid ? selector_uuid : MANAGE_NVT_SELECTOR_UUID_ALL,
         quoted_type,
         actual_usage_type,
         predefined);
  g_free (quoted_candidate_name);
  g_free (quoted_type);

  /* Insert the selectors into the nvt_selectors table. */

  *config = sql_last_insert_id ();

  if (selector_uuid && (config_type == NULL || strcmp (config_type, "0") == 0))
    {
      if ((ret = insert_nvt_selectors (selector_uuid, selectors, allow_errors)))
        {
          sql_rollback ();
          free (selector_uuid);
          return ret;
        }
    }
  free (selector_uuid);

  /* Insert the preferences into the config_preferences table. */

  if ((ret = config_insert_preferences (*config, preferences, config_type)))
    {
      sql_rollback ();
      return ret;
    }

  /* Update family and NVT count caches. */

  update_config_caches (*config);

  sql_commit ();
  *name = candidate_name;
  return 0;
}

/**
 * @brief Create a config.
 *
 * If a config with the same name exists already then add a unique integer
 * suffix onto the name.
 *
 * @param[in]   config_id      ID if one is required, else NULL.
 * @param[in]   proposed_name  Proposed name of config.
 * @param[in]   make_name_unique  Whether to make name unique.
 * @param[in]   comment        Comment on config.
 * @param[in]   all_selector   Whether to use "all" selector instead of selectors.
 * @param[in]   selectors      NVT selectors.
 * @param[in]   preferences    Preferences.
 * @param[in]   config_type    Config type.
 * @param[in]   usage_type     The usage type ("scan" or "policy")
 * @param[out]  config         On success the config.
 * @param[out]  name           On success the name of the config.
 *
 * @return 0 success, 1 config exists already, 99 permission denied, -1 error,
 *         -2 name empty, -3 input error in selectors, -4 input error in
 *         preferences, -5 error in config_id.
 */
int
create_config (const char *config_id, const char *proposed_name,
               int make_name_unique, const char *comment, int all_selector,
               const array_t *selectors /* nvt_selector_t. */,
               const array_t *preferences /* preference_t. */,
               const char *config_type, const char *usage_type,
               config_t *config, char **name)
{
  return create_config_internal (1, config_id, proposed_name, make_name_unique,
                                 comment, all_selector, selectors, preferences,
                                 config_type, usage_type, 1,
                                 0, /* Predefined. */
                                 config, name);
}

/**
 * @brief Create a config.
 *
 * If a config with the same name exists already then add a unique integer
 * suffix onto the name.
 *
 * @param[in]   config_id      ID if one is required, else NULL.
 * @param[in]   proposed_name  Proposed name of config.
 * @param[in]   make_name_unique  Whether to make name unique.
 * @param[in]   comment        Comment on config.
 * @param[in]   all_selector   Whether to use "all" selector instead of selectors.
 * @param[in]   selectors      NVT selectors.
 * @param[in]   preferences    Preferences.
 * @param[in]   config_type    Config type.
 * @param[in]   usage_type     The usage type ("scan" or "policy")
 * @param[out]  config         On success the config.
 * @param[out]  name           On success the name of the config.
 *
 * @return 0 success, 1 config exists already, 99 permission denied, -1 error,
 *         -2 name empty, -3 input error in selectors, -4 input error in
 *         preferences, -5 error in config_id.
 */
int
create_config_no_acl (const char *config_id, const char *proposed_name,
                      int make_name_unique, const char *comment,
                      int all_selector,
                      const array_t *selectors /* nvt_selector_t. */,
                      const array_t *preferences /* preference_t. */,
                      const char *config_type, const char *usage_type,
                      config_t *config, char **name)
{
  return create_config_internal (0, config_id, proposed_name, make_name_unique,
                                 comment, all_selector, selectors, preferences,
                                 config_type, usage_type, 0,
                                 1, /* Predefined. */
                                 config, name);
}

/**
 * @brief Get list of OSP Scanner parameters.
 *
 * @param[in]   scanner    Scanner.
 *
 * @return List of scanner parameters, NULL if error.
 */
static GSList *
get_scanner_params (scanner_t scanner)
{
  GSList *list = NULL;
  osp_connection_t *connection;

  connection = osp_scanner_connect (scanner);
  if (!connection)
    return NULL;

  osp_get_scanner_details (connection, NULL, &list);
  osp_connection_close (connection);
  return list;
}

/**
 * @brief Insert an OSP parameter into a config if not already present.
 *
 * @param[in]   param   OSP parameter to insert.
 * @param[in]   config  Config to insert parameter into.
 *
 * @return 1 if added, 0 otherwise.
 */
static int
insert_osp_parameter (osp_param_t *param, config_t config)
{
  char *param_id, *param_name, *param_type, *param_def, *param_value = NULL;
  int ret = 0;

  if (!param)
    return ret;
  param_id = sql_quote (osp_param_id (param));
  param_name = sql_quote (osp_param_name (param));
  param_type = sql_quote (osp_param_type_str (param));
  if (!strcmp (param_type, "selection"))
    {
      char **strarray = g_strsplit (osp_param_default (param), "|", 2);

      param_value = sql_quote (strarray[0] ?: "");
      param_def = sql_quote (strarray[1] ?: param_value);
      g_strfreev (strarray);
    }
  else
    param_def = sql_quote (osp_param_default (param));
  if (sql_int ("SELECT count(*) FROM config_preferences"
               " WHERE config = %llu AND name = '%s' AND type = '%s'"
               " AND default_value = '%s';",
               config, param_id, param_type, param_def) == 0)
    {
      sql ("INSERT INTO config_preferences (config, name, type, value,"
           " default_value, hr_name)"
           " VALUES (%llu, '%s', '%s', '%s', '%s', '%s')",
           config , param_id, param_type, param_value ?: param_def,
           param_def, param_name);
      ret = 1;
    }
  g_free (param_name);
  g_free (param_id);
  g_free (param_type);
  g_free (param_def);
  g_free (param_value);
  return ret;
}

/**
 * @brief  Generate an extra WHERE clause for selecting configs
 *
 * @param[in]  usage_type   The usage type to limit the selection to.
 *
 * @return Newly allocated where clause string.
 */
gchar *
configs_extra_where (const char *usage_type)
{
  gchar *extra_where = NULL;
  if (usage_type && strcmp (usage_type, ""))
    {
      gchar *quoted_usage_type;
      quoted_usage_type = sql_quote (usage_type);
      extra_where = g_strdup_printf (" AND usage_type = '%s'",
                                     quoted_usage_type);
      g_free (quoted_usage_type);
    }
  return extra_where;
}

/**
 * @brief Create a config from an OSP scanner.
 *
 * @param[in]   scanner_id  UUID of scanner to create config from.
 * @param[in]   name        Name for config.
 * @param[in]   comment     Comment for config.
 * @param[in]   usage_type  The usage type ("scan" or "policy")
 * @param[out]  uuid        Config UUID, on success.
 *
 * @return 0 success, 1 couldn't find scanner, 2 scanner not of OSP type,
 *         3 config name exists already, 4 couldn't get params from scanner,
 *         99 permission denied, -1 error.
 */
int
create_config_from_scanner (const char *scanner_id, const char *name,
                            const char *comment, const char *usage_type,
                            char **uuid)
{
  scanner_t scanner;
  config_t config;
  GSList *params, *element;
  char *quoted_name, *quoted_comment;
  const char *actual_usage_type;

  assert (current_credentials.uuid);
  assert (scanner_id);
  sql_begin_immediate ();

  if (acl_user_may ("create_config") == 0)
    {
      sql_rollback ();
      return 99;
    }
  if (find_scanner_with_permission (scanner_id, &scanner, "get_scanners"))
    {
      sql_rollback ();
      return -1;
    }
  if (scanner == 0)
    {
      sql_rollback ();
      return 1;
    }
  if (scanner_type (scanner) != SCANNER_TYPE_OSP)
    {
      sql_rollback ();
      return 2;
    }
  if (resource_with_name_exists (name, "config", 0))
    {
      sql_rollback ();
      return 3;
    }

  params = get_scanner_params (scanner);
  if (!params)
    {
      sql_rollback ();
      return 4;
    }
  quoted_name = sql_quote (name ?: "");
  quoted_comment = sql_quote (comment ?: "");
  if (usage_type && strcasecmp (usage_type, "policy") == 0)
    actual_usage_type = "policy";
  else
    actual_usage_type = "scan";

  /* Create new OSP config. */
  sql ("INSERT INTO configs (uuid, name, owner, nvt_selector, comment,"
       " type, scanner, creation_time, modification_time, usage_type)"
       " VALUES (make_uuid (), '%s',"
       " (SELECT id FROM users WHERE users.uuid = '%s'),"
       " '', '%s', 1, %llu, m_now (), m_now (), '%s');",
       quoted_name, current_credentials.uuid, quoted_comment, scanner,
       actual_usage_type);
  g_free (quoted_name);
  g_free (quoted_comment);
  config = sql_last_insert_id ();
  *uuid = config_uuid (config);

  element = params;
  while (element)
    {
      insert_osp_parameter (element->data, config);
      osp_param_free (element->data);
      element = element->next;
    }
  g_slist_free (params);
  sql_commit ();
  return 0;
}

/**
 * @brief Return the UUID of a config.
 *
 * @param[in]   config  Config.
 *
 * @return Newly allocated config uuid pointer.
 */
char *
config_uuid (config_t config)
{
  return sql_string ("SELECT uuid FROM configs WHERE id = %llu;", config);
}

/**
 * @brief Return the type of a config.
 *
 * @param[in]  config  Config.
 *
 * @return Config type, -1 if not found.
 */
int
config_type (config_t config)
{
  int type;
  char *str;
  str = sql_string ("SELECT type FROM configs WHERE id = %llu;", config);
  if (!str)
    return -1;
  type = atoi (str);
  g_free (str);
  return type;
}

/**
 * @brief Return the scanner associated with a config, if any.
 *
 * @param[in]  config   Config.
 *
 * @return Scanner ID if found, 0 otherwise.
 */
static scanner_t
config_scanner (config_t config)
{
  scanner_t scanner;

  switch (sql_int64 (&scanner,
                     "SELECT scanner FROM configs WHERE id = %llu;", config))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        return 0;
      case -1:
        return 0;
      default:       /* Programming error. */
        assert (0);
    }
  return scanner;
}

/**
 * @brief Return whether a config is predefined.
 *
 * @param[in]  config  Config.
 *
 * @return 1 if predefined, else 0.
 */
int
config_predefined (config_t config)
{
  return sql_int ("SELECT predefined FROM configs"
                  " WHERE id = %llu;",
                  config);
}

/**
 * @brief Return whether a trash config is predefined.
 *
 * @param[in]  config  Config.
 *
 * @return 1 if predefined, else 0.
 */
int
trash_config_predefined (config_t config)
{
  return sql_int ("SELECT predefined FROM configs_trash"
                  " WHERE id = %llu;",
                  config);
}

/**
 * @brief Get the timeout value for an NVT in a config.
 *
 * @param[in]  config  Config.
 * @param[in]  oid     ID of NVT.
 *
 * @return Newly allocated timeout if set for the NVT, else NULL.
 */
char *
config_nvt_timeout (config_t config, const char *oid)
{
  return sql_string ("SELECT value FROM config_preferences"
                     " WHERE config = %llu"
                     " AND type = 'SERVER_PREFS'"
                     " AND name = 'timeout.%s';",
                     config,
                     oid);
}

/**
 * @brief Check scanner and config values match for a task.
 *
 * @param[in]  config       Scan Config.
 * @param[in]  scanner      Scanner.
 *
 * @return 1 if config and scanner types match, 0 otherwise.
 */
int
create_task_check_config_scanner (config_t config, scanner_t scanner)
{
  int ctype, stype;

  assert (config);
  assert (scanner);

  ctype = config_type (config);
  stype = scanner_type (scanner);

  if (ctype == 0 && stype == SCANNER_TYPE_OPENVAS)
    return 1;
  if (ctype == 0 && stype == SCANNER_TYPE_OSP_SENSOR)
    return 1;
  if (ctype == 1 && stype == SCANNER_TYPE_OSP)
    return 1;

  return 0;
}

/**
 * @brief Check scanner and config values match for a task.
 *
 * @param[in]  task         Task.
 * @param[in]  config_id    ID of config. "0" to use task's config.
 * @param[in]  scanner_id   ID of scanner.
 *
 * @return 0 if config and scanner types match, 1 do not match, 2 failed to
 *         find config, 3 failed to find scanner, -1 error.
 */
int
modify_task_check_config_scanner (task_t task, const char *config_id,
                                  const char *scanner_id)
{
  config_t config = 0;
  scanner_t scanner = 0;
  int ctype, stype;

  if (config_id == NULL)
    config_id = "0";
  if (scanner_id == NULL)
    scanner_id = "0";

  if (!strcmp (config_id, "0") && !strcmp (scanner_id, "0"))
    return 0;

  if (strcmp (config_id, "0"))
    {
      if (find_config_with_permission (config_id, &config, "get_configs"))
        return -1;
      if (config == 0)
        return 2;
    }
  else
    config = task_config (task);

  if (strcmp (scanner_id, "0"))
    {
      if (find_scanner_with_permission (scanner_id, &scanner, "get_scanners"))
        return -1;
      if (scanner == 0)
        return 3;
    }
  else
    scanner = task_scanner (task);

  stype = scanner_type (scanner);

  /* CVE Scanner. */
  if (stype == SCANNER_TYPE_CVE)
    return strcmp (scanner_id, "0")
            /* Selecting the CVE Scanner will clear the config. */
            ? 0
            /* CVE Scanner is currently selected, so the only option is to
             * leave the config alone. */
            : (config ? 1 : 0);

  ctype = config_type (config);
  /* OSP Scanner with OSP config. */
  if (stype == SCANNER_TYPE_OSP && ctype == 1)
    return 0;

  /* OpenVAS Scanner with OpenVAS config. */
  if ((stype == SCANNER_TYPE_OPENVAS)
      && ctype == 0)
    return 0;

  /* OSP Sensor with OpenVAS config. */
  if (stype == SCANNER_TYPE_OSP_SENSOR && ctype == 0)
    return 0;

  /* Default Scanner with OpenVAS Config. */
  if (scanner == 0 && ctype == 0)
    return 0;

  return 1;
}

/**
 * @brief Create a config from an existing config.
 *
 * @param[in]  name        Name of new config and NVT selector.
 * @param[in]  comment     Comment on new config.
 * @param[in]  config_id   UUID of existing config.
 * @param[in]  usage_type  Optional new usage type for the new config.
 * @param[out] new_config  New config.
 *
 * @return 0 success, 1 config exists already, 2 failed to find existing
 *         config, 99 permission denied, -1 error.
 */
int
copy_config (const char* name, const char* comment, const char *config_id,
             const char* usage_type, config_t* new_config)
{
  int ret, type;
  char *config_selector;
  gchar *quoted_config_selector;
  config_t new, old;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  /* Copy the existing config. */

  ret = copy_resource_lock ("config", name, comment, config_id,
                            " family_count, nvt_count, families_growing,"
                            " nvts_growing, type, scanner, usage_type",
                            1, &new, &old);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  sql ("UPDATE configs SET predefined = 0 WHERE id = %llu;", new);

  sql ("INSERT INTO config_preferences (config, type, name, value,"
       "                                default_value, hr_name)"
       " SELECT %llu, type, name, value, default_value, hr_name"
       " FROM config_preferences"
       " WHERE config = %llu;", new, old);

  type = config_type (new);
  if (type > 0)
    {
      /* Don't create nvt_selector etc,. for non-standard configs
       * (eg. OSP config.) Only config preferences are copied.
       */
      sql_commit ();
      if (new_config) *new_config = new;
      return 0;
    }

  sql ("UPDATE configs SET nvt_selector = make_uuid () WHERE id = %llu;",
       new);

  if (usage_type && strcmp (usage_type, ""))
    {
      const char *actual_usage_type;

      if (strcasecmp (usage_type, "policy") == 0)
        actual_usage_type = "policy";
      else
        actual_usage_type = "scan";

      sql ("UPDATE configs SET usage_type = '%s' WHERE id = %llu;",
           actual_usage_type,
           new);
    }

  config_selector = config_nvt_selector (old);
  if (config_selector == NULL)
    {
      sql_rollback ();
      return -1;
    }
  quoted_config_selector = sql_quote (config_selector);
  free (config_selector);

  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " SELECT (SELECT nvt_selector FROM configs WHERE id = %llu),"
       "        exclude, type, family_or_nvt, family"
       " FROM nvt_selectors"
       " WHERE name = '%s';",
       new,
       quoted_config_selector);
  g_free (quoted_config_selector);

  sql_commit ();
  if (new_config) *new_config = new;
  return 0;
}

/**
 * @brief Delete a config.
 *
 * @param[in]  config_id  UUID of config.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the config, 2 failed to
 *         find config, 99 permission denied, -1 error.
 */
int
delete_config (const char *config_id, int ultimate)
{
  config_t config = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_config") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_config_with_permission (config_id, &config, "delete_config"))
    {
      sql_rollback ();
      return -1;
    }

  if (config == 0)
    {
      if (find_trash ("config", config_id, &config))
        {
          sql_rollback ();
          return -1;
        }
      if (config == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      /* Check if it's in use by a task in the trashcan. */
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE config = %llu"
                   " AND config_location = " G_STRINGIFY (LOCATION_TRASH) ";",
                   config))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("config", config, LOCATION_TRASH);
      tags_remove_resource ("config", config, LOCATION_TRASH);

      sql ("DELETE FROM nvt_selectors"
           " WHERE name != '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
           " AND name = (SELECT nvt_selector FROM configs_trash"
           "             WHERE id = %llu);",
           config);
      sql ("DELETE FROM config_preferences_trash WHERE config = %llu;",
           config);
      sql ("DELETE FROM configs_trash WHERE id = %llu;",
           config);
      sql_commit ();
      return 0;
    }

  if (ultimate)
    {
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE config = %llu"
                   " AND config_location = " G_STRINGIFY (LOCATION_TABLE),
                   config))
        {
          sql_rollback ();
          return 1;
        }

      sql ("DELETE FROM nvt_selectors"
           " WHERE name != '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
           " AND name = (SELECT nvt_selector FROM configs_trash"
           "             WHERE id = %llu);",
           config);

      permissions_set_orphans ("config", config, LOCATION_TABLE);
      tags_remove_resource ("config", config, LOCATION_TABLE);
    }
  else
    {
      config_t trash_config;

      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE config = %llu"
                   " AND config_location = " G_STRINGIFY (LOCATION_TABLE)
                   " AND hidden = 0;",
                   config))
        {
          sql_rollback ();
          return 1;
        }

      sql ("INSERT INTO configs_trash"
           " (uuid, owner, name, nvt_selector, comment, family_count,"
           "  nvt_count, families_growing, nvts_growing, type, scanner,"
           "  predefined, creation_time, modification_time,"
           "  scanner_location, usage_type)"
           " SELECT uuid, owner, name, nvt_selector, comment, family_count,"
           "        nvt_count, families_growing, nvts_growing, type, scanner,"
           "        predefined, creation_time, modification_time,"
           "        " G_STRINGIFY (LOCATION_TABLE) ", usage_type"
           " FROM configs WHERE id = %llu;",
           config);

      trash_config = sql_last_insert_id ();

      sql ("INSERT INTO config_preferences_trash"
           " (config, type, name, value, default_value, hr_name)"
           " SELECT %llu, type, name, value, default_value, hr_name"
           " FROM config_preferences WHERE config = %llu;",
           trash_config,
           config);

      /* Update the location of the config in any trashcan tasks. */
      sql ("UPDATE tasks"
           " SET config = %llu,"
           "     config_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE config = %llu"
           " AND config_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           trash_config,
           config);

      permissions_set_locations ("config", config, trash_config,
                                 LOCATION_TRASH);
      tags_set_locations ("config", config, trash_config,
                          LOCATION_TRASH);
    }

  sql ("DELETE FROM config_preferences WHERE config = %llu;", config);
  sql ("DELETE FROM configs WHERE id = %llu;", config);

  sql_commit ();
  return 0;
}

/**
 * @brief Update a config with a list of parameters.
 *
 * @param[in]  config       Config ID.
 * @param[in]  config_id    Config UUID.
 * @param[in]  params       List of new config parameters.
 *
 */
static void
update_config_params (config_t config, const char *config_id, GSList *params)
{
  GSList *element;
  iterator_t iterator;

  /* Remove parameters not used anymore. */
  init_iterator (&iterator,
                 "SELECT id, name, type, default_value, hr_name"
                 " FROM config_preferences"
                 " WHERE config = %llu;", config);
  while (next (&iterator))
    {
      int found = 0;

      element = params;
      while (element)
        {
          const char *name, *type, *def;

          name = osp_param_id (element->data);
          type = osp_param_type_str (element->data);
          def = osp_param_default (element->data);
          if (!strcmp (name,  iterator_string (&iterator, 1))
              && !strcmp (type, iterator_string (&iterator, 2)))
            {
              const char *iter_def = iterator_string (&iterator, 3);

              if (!strcmp (type, "selection")
                  && !strcmp (strchr (def, '|') + 1, iter_def))
                found = 1;
              else if (strcmp (type, "selection") && !strcmp (def, iter_def))
                found = 1;
              if (found)
                break;
            }
          element = element->next;
        }
      if (!found)
        {
          g_message ("Removing config preference %s from config '%s'",
                     iterator_string (&iterator, 1), config_id);
          sql ("DELETE FROM config_preferences WHERE id = %llu;",
               iterator_int64 (&iterator, 0));
        }
      else if (strcmp (osp_param_name (element->data),
                       iterator_string (&iterator, 4)))
        {
          // Update hr_name (= OSP name)
          gchar *quoted_name;
          quoted_name = sql_quote (osp_param_name (element->data));
          g_message ("Updating name of config preference %s in config '%s'",
                     iterator_string (&iterator, 1), config_id);
          sql ("UPDATE config_preferences SET hr_name='%s' WHERE id = %llu;",
               quoted_name,
               iterator_int64 (&iterator, 0));
          g_free (quoted_name);
        }
    }
  cleanup_iterator (&iterator);
  /* Insert new parameters. */
  element = params;
  while (element)
    {
      if (insert_osp_parameter (element->data, config))
        g_message ("Adding config preference %s to config '%s'",
                   osp_param_id (element->data), config_id);
      element = element->next;
    }
}

/**
 * @brief Synchronize a config.
 *
 * @param[in]  config_id  UUID of config.
 *
 * @return 0 success, 1 failed to find config, 2 config not of OSP type,
 *         3 config has no scanner, 4 couldn't get params from scanner,
 *         99 permission denied, -1 error.
 */
int
sync_config (const char *config_id)
{
  config_t config = 0;
  GSList *params;
  scanner_t scanner;

  assert (config_id);
  assert (current_credentials.uuid);

  sql_begin_immediate ();

  if (acl_user_may ("modify_config") == 0)
    {
      sql_rollback ();
      return 99;
    }
  if (find_config_with_permission (config_id, &config, "modify_config"))
    {
      sql_rollback ();
      return -1;
    }
  if (config == 0)
    {
      sql_rollback ();
      return 1;
    }
  if (config_type (config) != SCANNER_TYPE_OSP)
    {
      sql_rollback ();
      return 2;
    }
  scanner = config_scanner (config);
  if (!scanner)
    {
      sql_rollback ();
      return 3;
    }
  params = get_scanner_params (scanner);
  if (!params)
    {
      sql_rollback ();
      return 4;
    }
  update_config_params (config, config_id, params);

  sql_commit ();
  while (params)
    {
      osp_param_free (params->data);
      params = g_slist_remove_link (params, params);
    }
  return 0;
}

/**
 * @brief Count the number of scan configs.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of scan configs filtered set.
 */
int
config_count (const get_data_t *get)
{
  int rc;
  static const char *filter_columns[] = CONFIG_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CONFIG_ITERATOR_COLUMNS;
  static column_t trash_columns[] = CONFIG_ITERATOR_TRASH_COLUMNS;
  const char *usage_type = get_data_get_extra (get, "usage_type");
  gchar *extra_where = configs_extra_where (usage_type);

  rc = count ("config", get, columns, trash_columns, filter_columns,
              0, 0, extra_where, TRUE);

  g_free (extra_where);
  return rc;
}

/**
 * @brief Initialise a config iterator, limited to user's configs.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  config      Config.  0 for all.
 * @param[in]  trash       Whether to iterate over trashcan configs.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_user_config_iterator (iterator_t* iterator, config_t config, int trash,
                           int ascending, const char* sort_field)
{
  static column_t select_columns[] = CONFIG_ITERATOR_COLUMNS;
  gchar *columns;
  gchar *sql;

  assert (current_credentials.uuid);

  columns = columns_build_select (select_columns);
  if (config)
    sql = g_strdup_printf ("SELECT %s"
                           " FROM configs%s"
                           " WHERE id = %llu"
                           " AND " ACL_USER_OWNS ()
                           " ORDER BY %s %s;",
                           columns,
                           trash ? "_trash" : "",
                           config,
                           current_credentials.uuid,
                           sort_field ? sort_field : "id",
                           ascending ? "ASC" : "DESC");
  else
    sql = g_strdup_printf ("SELECT %s"
                           " FROM configs%s"
                           " WHERE " ACL_USER_OWNS ()
                           " ORDER BY %s %s;",
                           columns,
                           trash ? "_trash" : "",
                           current_credentials.uuid,
                           sort_field ? sort_field : "id",
                           ascending ? "ASC" : "DESC");
  g_free (columns);
  init_iterator (iterator, "%s", sql);
  g_free (sql);
}

/**
 * @brief Initialise a scan config iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find scan config, 2 failed to find filter,
 *         -1 error.
 */
int
init_config_iterator (iterator_t* iterator, const get_data_t *get)
{
  int rc;
  static const char *filter_columns[] = CONFIG_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CONFIG_ITERATOR_COLUMNS;
  static column_t trash_columns[] = CONFIG_ITERATOR_TRASH_COLUMNS;
  const char *usage_type = get_data_get_extra (get, "usage_type");
  gchar *extra_where = configs_extra_where (usage_type);

  rc = init_get_iterator (iterator,
                          "config",
                          get,
                          columns,
                          trash_columns,
                          filter_columns,
                          0,
                          NULL,
                          extra_where,
                          TRUE);
  g_free (extra_where);
  return rc;
}

/**
 * @brief Get the nvt_selector from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The nvt_selector of the config, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (config_iterator_nvt_selector, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the family count from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Family count if known, -1 else.
 */
int
config_iterator_family_count (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
  return ret;
}

/**
 * @brief Get the nvt count from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Nvt count if known, -1 else.
 */
int
config_iterator_nvt_count (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
  return ret;
}

/**
 * @brief Get the families growing state from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Families growing flag.
 */
int
config_iterator_families_growing (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT +3);
  return ret;
}

/**
 * @brief Get the NVTs growing state from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVTs growing flag.
 */
int
config_iterator_nvts_growing (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
  return ret;
}

/**
 * @brief Get the type from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Config type.
 */
int
config_iterator_type (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
  return ret;
}

/**
 * @brief Get the scanner from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Scanner.
 */
scanner_t
config_iterator_scanner (iterator_t* iterator)
{
  scanner_t ret = 0;
  if (iterator->done) return 0;
  ret = iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 6);
  return ret;
}

/**
 * @brief Get whether scanner is in trash from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether Scanner is in trash.
 */
int
config_iterator_scanner_trash (iterator_t* iterator)
{
  int ret = 0;
  if (iterator->done) return 0;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
  return ret;
}

/**
 * @brief Get the usage type from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The usage type of the config, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (config_iterator_usage_type, GET_ITERATOR_COLUMN_COUNT + 8);

/**
 * @brief Get predefined status from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if predefined, else 0.
 */
int
config_iterator_predefined (iterator_t* iterator)
{
  int ret = 0;
  if (iterator->done) return 0;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 9);
  return ret;
}

/**
 * @brief Return whether a config is referenced by a task.
 *
 * @param[in]  config  Config.
 *
 * @return 1 if in use, else 0.
 */
int
config_in_use (config_t config)
{
  return !!sql_int ("SELECT count(*) FROM tasks"
                    " WHERE config = %llu"
                    " AND config_location = " G_STRINGIFY (LOCATION_TABLE)
                    " AND hidden = 0;",
                    config);
}

/**
 * @brief Return whether a config can be modified.
 *
 * @param[in]  config  Config.
 *
 * @return 1.
 */
int
config_writable (config_t config)
{
  return 1;
}

/**
 * @brief Return whether a trashcan config is referenced by a task.
 *
 * @param[in]  config  Config.
 *
 * @return 1 if in use, else 0.
 */
int
trash_config_in_use (config_t config)
{
  return !!sql_int ("SELECT count(*) FROM tasks"
                    " WHERE config = %llu"
                    " AND config_location = " G_STRINGIFY (LOCATION_TRASH),
                    config);
}

/**
 * @brief Return whether a trashcan config is writable.
 *
 * @param[in]  config  Config.
 *
 * @return 1 if in use, else 0.
 */
int
trash_config_writable (config_t config)
{
  return !trash_config_in_use (config);
}

/**
 * @brief Return whether a trashcan config is readable.
 *
 * @param[in]  config_id  Config UUID.
 *
 * @return 1 if readable, else 0.
 */
int
trash_config_readable_uuid (const gchar *config_id)
{
  config_t found;

  found = 0;
  if (find_trash ("config", config_id, &found))
    return 0;
  return found > 0;
}

/**
 * @brief Initialise a preference iterator.
 *
 * Assume the caller has permission to access the config.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  config    Config.
 */
void
init_config_preference_iterator (iterator_t* iterator, config_t config)
{
  gchar* sql;

  sql = g_strdup_printf ("SELECT name, value, type, default_value, hr_name"
                         " FROM config_preferences"
                         " WHERE config = %llu;",
                         config);
  init_iterator (iterator, "%s", sql);
  g_free (sql);
}

/**
 * @brief Get the name from a preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * Note: For OSP results this corresponds to the "id" field in OSP, not "name".
 *
 * @return The name of the preference iterator, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (config_preference_iterator_name, 0);

/**
 * @brief Get the value from a preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the preference iterator, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (config_preference_iterator_value, 1);

/**
 * @brief Get the type from a preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the preference iterator, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (config_preference_iterator_type, 2);

/**
 * @brief Get the default from a preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The default of the preference iterator, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (config_preference_iterator_default, 3);

/**
 * @brief Get the hr_name from a preference iterator.
 *
 * Note: This corresponds to the "name" in OSP and is not defined for classic
 *  OpenVAS config preferences.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The hr_name of the preference iterator, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (config_preference_iterator_hr_name, 4);

/**
 * @brief Initialise a config preference iterator, with defaults.
 *
 * Assume the caller has permission to access the config.
 *
 * This version substitutes the NVT preference when the config preference
 * is missing.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  config    Config containing preferences.
 * @param[in]  section   Preference section.
 */
void
init_preference_iterator (iterator_t* iterator,
                          config_t config,
                          const char* section)
{
  gchar *quoted_section;

  assert (config);
  assert (section);
  assert ((strcmp (section, "PLUGINS_PREFS") == 0)
          || (strcmp (section, "SERVER_PREFS") == 0));

  quoted_section = sql_quote (section);

  init_iterator (iterator,
                 "SELECT config_preferences.name, config_preferences.value"
                 " FROM config_preferences, nvt_preferences"
                 " WHERE config_preferences.config = %llu"
                 " AND config_preferences.type = '%s'"
                 " AND (config_preferences.name = nvt_preferences.name"
                 "      OR config_preferences.name LIKE 'timeout.%%')"
                 " AND config_preferences.name != 'max_checks'"
                 " AND config_preferences.name != 'max_hosts'"
                 " UNION"
                 " SELECT nvt_preferences.name, nvt_preferences.value"
                 " FROM nvt_preferences"
                 " WHERE nvt_preferences.name %s"
                 " AND (SELECT COUNT(*) FROM config_preferences"
                 "      WHERE config = %llu"
                 "      AND config_preferences.name = nvt_preferences.name) = 0;",
                 config,
                 quoted_section,
                 strcmp (quoted_section, "SERVER_PREFS") == 0
                  ? "NOT LIKE '%:%:%:%'" : "LIKE '%:%:%:%'",
                 config);
  g_free (quoted_section);
}

/**
 * @brief Get the NAME from a preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NAME, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (preference_iterator_name, 0);

/**
 * @brief Get the value from a preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (preference_iterator_value, 1);

/**
 * @brief Return the NVT selector associated with a config.
 *
 * @param[in]  config  Config.
 *
 * @return Name of NVT selector if config exists and NVT selector is set, else
 *         NULL.
 */
char*
config_nvt_selector (config_t config)
{
  return sql_string ("SELECT nvt_selector FROM configs WHERE id = %llu;",
                     config);
}

/**
 * @brief Update a preference of a config.
 *
 * @param[in]  config      Config.
 * @param[in]  nvt         UUID of NVT.  NULL for scanner preference.
 * @param[in]  name        Preference name, including NVT name and preference
 *                         type.
 * @param[in]  value_64    Preference value in base64.  NULL for an NVT
 *                         preference removes the preference from the config.
 *
 * @return 0 success, 1 config in use, 2 empty radio value, 3 failed to find
 *         config, -1 error.
 */
static int
modify_config_preference (config_t config, const char* nvt,
                          const char* name, const char* value_64)
{
  gchar *quoted_name, *quoted_value, *value, **splits;

  quoted_name = sql_quote (name);

  if (strlen (value_64))
    {
      gsize value_len;
      value = (gchar*) g_base64_decode (value_64, &value_len);
    }
  else
    value = g_strdup ("");

  /* OID:PrefID:PrefType:PrefName value */
  splits = g_strsplit (name, ":", 4);
  if (splits && g_strv_length (splits) == 4)
    {
      if (strcmp (splits[2], "radio") == 0)
        {
          char *old_value;
          gchar **split, **point;
          GString *string;

          if (strlen (value) == 0)
            {
              g_free (quoted_name);
              g_free (value);
              return 2;
            }

          /* A radio.  Put the new value on the front of the list of options. */

          old_value = sql_string ("SELECT value FROM config_preferences"
                                  " WHERE config = %llu"
                                  " AND type %s"
                                  " AND name = '%s'",
                                  config,
                                  nvt ? "= 'PLUGINS_PREFS'" : "is NULL",
                                  quoted_name);
          if (old_value == NULL)
            old_value = sql_string ("SELECT value FROM nvt_preferences"
                                    " WHERE name = '%s'",
                                    quoted_name);
          if (old_value)
            {
              string = g_string_new (value);
              split = g_strsplit (old_value, ";", 0);
              free (old_value);
              point = split;
              while (*point)
                {
                  if (strlen (*point) == 0)
                    {
                      g_free (quoted_name);
                      g_strfreev (split);
                      g_free (value);
                      g_string_free (string, TRUE);
                      return -1;
                    }

                  if (strcmp (*point, value))
                    {
                      g_string_append_c (string, ';');
                      g_string_append (string, *point);
                    }
                  point++;
                }
              g_strfreev (split);
              g_free (value);
              value = g_string_free (string, FALSE);
            }
        }
      else if (strcmp (splits[2], "scanner") == 0)
        {
          /* A scanner preference.  Remove type decoration from name. */

          g_free (quoted_name);
          quoted_name = sql_quote (splits[3]);
        }
    }
  g_strfreev (splits);

  quoted_value = sql_quote ((gchar*) value);
  g_free (value);

  if (config_type (config) > 0)
    sql ("UPDATE config_preferences SET value = '%s'"
         " WHERE config = %llu AND name = '%s';",
         quoted_value, config, quoted_name);
  else
    {
      /* nvt prefs are not present on first modification. */
      sql ("DELETE FROM config_preferences"
           " WHERE config = %llu AND type %s AND name = '%s'",
           config,
           nvt ? "= 'PLUGINS_PREFS'" : "= 'SERVER_PREFS'",
           quoted_name);
      sql ("INSERT INTO config_preferences"
           " (config, type, name, value) VALUES (%llu, %s, '%s', '%s');",
           config, nvt ? "'PLUGINS_PREFS'" : "'SERVER_PREFS'", quoted_name,
           quoted_value);
    }

  return 0;
}

/**
 * @brief Set a preference of a config.
 *
 * @param[in]  config      Config to modify.
 * @param[in]  nvt         UUID of NVT.  NULL for scanner preference.
 * @param[in]  name        Preference name, including NVT name and preference
 *                         type.
 * @param[in]  value_64    Preference value in base64.  NULL for an NVT
 *                         preference removes the preference from the config.
 *
 * @return 0 success, 1 config in use, 2 empty radio value, -1 error.
 */
int
manage_set_config_preference (config_t config, const char* nvt,
                              const char* name, const char* value_64)
{
  int ret;

  if (value_64 == NULL)
    {
      gchar *quoted_name, **splits;

      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE config = %llu AND hidden = 0;",
                   config))
        {
          return 1;
        }

      quoted_name = sql_quote (name);

      /* OID:PrefID:scanner:PrefName */
      splits = g_strsplit (name, ":", 4);
      if (splits && g_strv_length (splits) == 4
          && strcmp (splits[2], "scanner") == 0)
        {
          /* A scanner preference.  Remove type decoration from name. */
          g_free (quoted_name);
          quoted_name = sql_quote (splits[3]);
        }
      g_strfreev (splits);

      sql ("DELETE FROM config_preferences"
           " WHERE config = %llu"
           " AND name = '%s';",
           config,
           quoted_name);

      g_free (quoted_name);
      return 0;
    }

  if (sql_int ("SELECT count(*) FROM tasks"
               " WHERE config = %llu AND hidden = 0;",
               config))
    {
      return 1;
    }

  ret = modify_config_preference (config, nvt, name, value_64);
  if (ret)
    {
      return ret;
    }

  return 0;
}

/**
 * @brief Set the name, comment and scanner of a config.
 *
 * @param[in]  config       Config to modify.
 * @param[in]  name         New name, not updated if NULL.
 * @param[in]  comment      New comment, not updated if NULL.
 * @param[in]  scanner_id   UUID of new scanner, not updated if NULL.
 *
 * @return 0 success, 1 config with new name exists already, 2 scanner doesn't
 *         exist, 3 modification not allowed while config is in use, -1 error.
 */
int
manage_set_config (config_t config, const char *name, const char *comment,
                   const char *scanner_id)
{
  assert (current_credentials.uuid);

  if (name)
    {
      gchar *quoted_name;
      if (resource_with_name_exists (name, "config", config))
        {
          return 1;
        }
      quoted_name = sql_quote (name);
      sql ("UPDATE configs SET name = '%s', modification_time = m_now ()"
           " WHERE id = %llu;", quoted_name, config);
      g_free (quoted_name);
    }
  if (comment)
    {
      gchar *quoted_comment;
      quoted_comment = sql_quote (comment);
      sql ("UPDATE configs SET comment = '%s', modification_time = m_now ()"
           " WHERE id = %llu;", quoted_comment, config);
      g_free (quoted_comment);
    }
  if (scanner_id)
    {
      if (config_in_use (config))
        {
          return 3;
        }
      scanner_t scanner = 0;

      if (find_scanner_with_permission (scanner_id, &scanner, "get_scanners")
          || scanner == 0)
        {
          return 2;
        }
      sql ("UPDATE configs SET scanner = %llu, modification_time = m_now ()"
           " WHERE id = %llu;", scanner, config);
    }
  return 0;
}

/**
 * @brief Check whether a family is "whole-only".
 *
 * @param[in]  family         Family name.
 *
 * @return 1 if whole-only, else 0.
 */
int
family_whole_only (const gchar *family)
{
  static const gchar *wholes[] = FAMILIES_WHOLE_ONLY;

  for (const gchar **whole = wholes; *whole; whole++)
    if (strcmp (*whole, family) == 0)
      return 1;
  return 0;
}

/**
 * @brief Get whether a config selects every NVT in a given family.
 *
 * @param[in]  config      Config.
 * @param[in]  family      Family name.
 *
 * @return 0 no, 1 yes, -1 error.
 */
int
config_family_entire_and_growing (config_t config, const char* family)
{
  char *selector;
  int ret;

  if (config == 0)
    return 0;

  selector = config_nvt_selector (config);
  if (selector == NULL)
    {
      /* The config should always have a selector. */
      return -1;
    }

  ret = nvt_selector_entire_and_growing (selector,
                                         family,
                                         config_families_growing (config));
  free (selector);

  return ret;
}

/**
 * @brief Set the NVT's selected for a single family of a config.
 *
 * @param[in]  config         Config to modify.
 * @param[in]  family         Family name.
 * @param[in]  selected_nvts  NVT's.
 *
 * @return 0 success, 1 config in use, 2 whole-only family, -1 error.
 */
int
manage_set_config_nvts (config_t config, const char* family,
                        GPtrArray* selected_nvts)
{
  char *selector;
  gchar *quoted_family, *quoted_selector;
  int new_nvt_count = 0, old_nvt_count;

  if (family_whole_only (family))
    return 2;

  if (sql_int ("SELECT count(*) FROM tasks"
               " WHERE config = %llu AND hidden = 0;",
               config))
    {
      return 1;
    }

  quoted_family = sql_quote (family);

  selector = config_nvt_selector (config);
  if (selector == NULL)
    {
      /* The config should always have a selector. */
      g_free (quoted_family);
      return -1;
    }

  quoted_selector = sql_quote (selector);

  /* If the family is growing, then exclude all no's, otherwise the family
   * is static, so include all yes's. */

  if (nvt_selector_family_growing (selector,
                                   family,
                                   config_families_growing (config)))
    {
      iterator_t nvts;

      old_nvt_count = nvt_selector_nvt_count (selector, family, 1);

      free (selector);

      /* Clear any NVT selectors for this family from the config. */

      if (strcmp (quoted_selector, MANAGE_NVT_SELECTOR_UUID_ALL))
        sql ("DELETE FROM nvt_selectors"
             " WHERE name = '%s'"
             " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
             " AND family = '%s';",
             quoted_selector,
             quoted_family);

      /* Exclude all no's. */

      new_nvt_count = family_nvt_count (family);

      init_nvt_iterator (&nvts, (nvt_t) 0, config, family, NULL, 1, NULL);
      while (next (&nvts))
        {
          const char *oid = nvt_iterator_oid (&nvts);
          gchar *quoted_oid;

          if (member (selected_nvts, oid)) continue;

          quoted_oid = sql_quote (oid);
          sql ("INSERT INTO nvt_selectors"
               " (name, exclude, type, family_or_nvt, family)"
               " VALUES ('%s', 1, "
               G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
               ", '%s', '%s');",
               quoted_selector,
               quoted_oid,
               quoted_family);
          g_free (quoted_oid);

          new_nvt_count--;
        }
      cleanup_iterator (&nvts);
    }
  else
    {
      old_nvt_count = nvt_selector_nvt_count (selector, family, 0);

      free (selector);

      /* Clear any NVT selectors for this family from the config. */

      if (strcmp (quoted_selector, MANAGE_NVT_SELECTOR_UUID_ALL))
        sql ("DELETE FROM nvt_selectors"
             " WHERE name = '%s'"
             " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
             " AND family = '%s';",
             quoted_selector,
             quoted_family);

      /* Include all yes's. */

      if (selected_nvts)
        {
          gchar *nvt;
          new_nvt_count = 0;

          while ((nvt = (gchar*) g_ptr_array_index (selected_nvts,
                                                    new_nvt_count)))
            {
              gchar *quoted_nvt = sql_quote (nvt);
              sql ("INSERT INTO nvt_selectors"
                   " (name, exclude, type, family_or_nvt, family)"
                   " VALUES ('%s', 0, "
                   G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                   ", '%s', '%s');",
                   quoted_selector,
                   quoted_nvt,
                   quoted_family);
              g_free (quoted_nvt);
              new_nvt_count++;
            }
        }
    }

  /* Update the cached config info. */

  sql ("UPDATE configs SET family_count = family_count + %i,"
       " nvt_count = nvt_count - %i + %i,"
       " modification_time = m_now ()"
       " WHERE id = %llu;",
       old_nvt_count == 0
        ? (new_nvt_count == 0 ? 0 : 1)
        : (new_nvt_count == 0 ? -1 : 0),
       old_nvt_count,
       MAX (new_nvt_count, 0),
       config);

  g_free (quoted_family);
  g_free (quoted_selector);
  return 0;
}

/**
 * @brief Switch between constraining and generating representation.
 *
 * It's up to the caller to start and end a transaction.
 *
 * @param[in]  config        Config name.
 * @param[in]  constraining  1 families currently growing, 0 families currently
 *                           static.
 *
 * @return 0 success, -1 error.
 */
static int
switch_representation (config_t config, int constraining)
{
  char* selector;
  gchar *quoted_selector;

  selector = config_nvt_selector (config);
  if (selector == NULL)
    return -1;
  quoted_selector = sql_quote (selector);

  if (constraining)
    {
      iterator_t families;

      /* Currently constraining the universe. */

      /* Remove the all selector. */

      nvt_selector_remove_selector (quoted_selector,
                                    NULL,
                                    NVT_SELECTOR_TYPE_ALL);

      /* Convert each family. */

      init_family_iterator (&families, 0, NULL, 1);
      while (next (&families))
        {
          const char *family = family_iterator_name (&families);
          if (family)
            {
              gchar *quoted_family = sql_quote (family);
              if (nvt_selector_family_growing (selector, family, 1))
                /* Add a family include. */
                nvt_selector_add (quoted_selector,
                                  quoted_family,
                                  NULL,
                                  0);
              else
                /* Remove the family exclude. */
                nvt_selector_remove_selector (quoted_selector,
                                              quoted_family,
                                              NVT_SELECTOR_TYPE_FAMILY);
              g_free (quoted_family);
            }
        }
      cleanup_iterator (&families);

      /* Update the cached config info. */

      sql ("UPDATE configs SET families_growing = 0 WHERE id = %llu;",
           config);
    }
  else
    {
      iterator_t families;

      /* Currently generating from empty. */

      /* Add the all selector. */

      sql ("INSERT INTO nvt_selectors"
           " (name, exclude, type, family_or_nvt)"
           " VALUES ('%s', 0, 0, 0);",
           quoted_selector);

      /* Convert each family. */

      init_family_iterator (&families, 0, NULL, 1);
      while (next (&families))
        {
          const char *family = family_iterator_name (&families);
          if (family)
            {
              gchar *quoted_family = sql_quote (family);
              if (nvt_selector_family_growing (selector, family, 0))
                /* Remove the family include. */
                nvt_selector_remove_selector (quoted_selector,
                                              quoted_family,
                                              NVT_SELECTOR_TYPE_FAMILY);
              else
                /* Add a family exclude. */
                nvt_selector_add (quoted_selector,
                                  quoted_family,
                                  NULL,
                                  1);
              g_free (quoted_family);
            }
        }
      cleanup_iterator (&families);

      /* Update the cached config info. */

      sql ("UPDATE configs SET families_growing = 1 WHERE id = %llu;",
           config);
    }

  free (selector);
  g_free (quoted_selector);
  return 0;
}

/**
 * @brief Initialise a config task iterator.
 *
 * Iterate over all tasks that use the config.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  config     Config.
 * @param[in]  ascending  Whether to sort ascending or descending.
 */
void
init_config_task_iterator (iterator_t* iterator, config_t config,
                           int ascending)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (config);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_tasks"));
  available = acl_where_owned ("task", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT name, uuid, %s FROM tasks"
                 " WHERE config = %llu"
                 " AND hidden = 0"
                 " ORDER BY name %s;",
                 with_clause ? with_clause : "",
                 available,
                 config,
                 ascending ? "ASC" : "DESC");

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the name from a config_task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (config_task_iterator_name, 0);

/**
 * @brief Get the UUID from a config_task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (config_task_iterator_uuid, 1);

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
config_task_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 2);
}

/**
 * @brief Initialise a config timeout iterator.
 *
 * Iterate over all timeout preferences of NVTs that have timeouts.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  config     Config.
 */
void
init_config_timeout_iterator (iterator_t* iterator, config_t config)
{
  init_iterator (iterator,
                 "SELECT name, substr (name, 9),"
                 "       (SELECT name FROM nvts"
                 "        WHERE oid = substr (config_preferences.name, 9)),"
                 "       value"
                 " FROM config_preferences"
                 " WHERE config = %llu"
                 " AND substr (name, 1, 8) = 'timeout.'"
                 /* Ensure that the NVT pref comes first, in case an
                  * error in the GSA added the NVT pref as a Scanner
                  * pref. */
                 " ORDER BY type",
                 config);
}

/**
 * @brief Get the NVT OID from a config timeout iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT OID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (config_timeout_iterator_oid, 1);

/**
 * @brief Get the NVT OID from a config timeout iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT OID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (config_timeout_iterator_nvt_name, 2);

/**
 * @brief Get the value from a config timeout iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Timeout value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (config_timeout_iterator_value, 3);

/**
 * @brief Update or optionally insert a NVT preference.
 *
 * @param[in]  config_id        UUID of the config to set the preference in
 * @param[in]  type             Type of the preference, e.g. "PLUGINS_PREFS"
 * @param[in]  preference_name  Full name of the preference
 * @param[in]  new_value        The new value to set
 * @param[in]  insert           Whether to insert the preference if missing
 */
void
update_config_preference (const char *config_id,
                          const char *type,
                          const char *preference_name,
                          const char *new_value,
                          gboolean insert)
{
  gchar *quoted_config_id = sql_quote (config_id);
  gchar *quoted_type = sql_quote (type);
  gchar *quoted_name = sql_quote (preference_name);
  gchar *quoted_value = sql_quote (new_value);

  if (sql_int ("SELECT count (*) FROM config_preferences"
               " WHERE config = (SELECT id FROM configs WHERE uuid = '%s')"
               "   AND type = '%s'"
               "   AND name = '%s';",
               quoted_config_id, quoted_type, quoted_name) == 0)
    {
      if (insert)
        {
          sql ("INSERT INTO config_preferences (config, type, name, value)"
               " VALUES ((SELECT id FROM configs WHERE uuid = '%s'),"
               "         '%s', '%s', '%s');",
               quoted_config_id, quoted_type, quoted_name, quoted_value);
        }
    }
  else
    {
      sql ("UPDATE config_preferences SET value = '%s'"
           " WHERE config = (SELECT id FROM configs WHERE uuid = '%s')"
           "   AND type = '%s'"
           "   AND name = '%s';",
           quoted_value, quoted_config_id, quoted_type, quoted_name);
    }

  g_free (quoted_config_id);
  g_free (quoted_type);
  g_free (quoted_name);
  g_free (quoted_value);
}

/**
 * @brief Update the cached count and growing information in a config.
 *
 * It's up to the caller to organise a transaction.
 *
 * @param[in]  configs  Config to update.
 */
static void
update_config_cache (iterator_t *configs)
{
  const char *selector;
  gchar *quoted_selector, *quoted_name;
  int families_growing;

  if (config_iterator_type (configs) > 0)
    return;

  quoted_name = sql_quote (get_iterator_name (configs));
  selector = config_iterator_nvt_selector (configs);
  families_growing = nvt_selector_families_growing (selector);
  quoted_selector = sql_quote (selector);

  sql ("UPDATE configs"
       " SET family_count = %i, nvt_count = %i,"
       " families_growing = %i, nvts_growing = %i"
       " WHERE name = '%s';",
       nvt_selector_family_count (quoted_selector, families_growing),
       nvt_selector_nvt_count (quoted_selector, NULL, families_growing),
       families_growing,
       nvt_selector_nvts_growing_2 (quoted_selector, families_growing),
       quoted_name);

  g_free (quoted_name);
  g_free (quoted_selector);
}

/**
 * @brief Update the cached count and growing information in every config.
 *
 * Only consider configs for the current user.
 *
 * It's up to the caller to organise a transaction.
 *
 * @param[in]  config  Config to update.  0 for all.
 */
static void
update_config_caches (config_t config)
{
  iterator_t configs;

  init_user_config_iterator (&configs, config, 0, 1, NULL);
  while (next (&configs))
    update_config_cache (&configs);
  cleanup_iterator (&configs);
}

/**
 * @brief Update count and growing info in every config across all users.
 *
 * It's up to the caller to organise a transaction.
 */
void
update_all_config_caches ()
{
  static column_t select_columns[] = CONFIG_ITERATOR_COLUMNS;
  gchar *columns;
  iterator_t configs;

  columns = columns_build_select (select_columns);
  init_iterator (&configs, "SELECT %s FROM configs;", columns);
  g_free (columns);
  while (next (&configs))
    update_config_cache (&configs);
  cleanup_iterator (&configs);
}

/**
 * @brief Update count and growing info in config, without checking user.
 *
 * For use during initialisation.
 *
 * @param[in]  uuid  Config UUID.
 *
 * It's up to the caller to organise a transaction.
 */
void
update_config_cache_init (const char *uuid)
{
  static column_t select_columns[] = CONFIG_ITERATOR_COLUMNS;
  gchar *columns;
  iterator_t configs;

  columns = columns_build_select (select_columns);
  init_iterator (&configs,
                 "SELECT %s FROM configs WHERE uuid = '%s';",
                 columns,
                 uuid);
  g_free (columns);
  while (next (&configs))
    update_config_cache (&configs);
  cleanup_iterator (&configs);
}

/**
 * @brief Migrate old ownerless configs to the Feed Owner.
 */
void
migrate_predefined_configs ()
{
  sql ("UPDATE configs"
       " SET owner = (SELECT id FROM users"
       "              WHERE uuid = (SELECT value FROM settings"
       "                            WHERE uuid = '%s'))"
       " WHERE owner is NULL;",
       SETTING_UUID_FEED_IMPORT_OWNER);
}


/* Startup. */

/**
 * @brief Check if a config has been updated in the feed.
 *
 * @param[in]  path    Full path to config XML in feed.
 * @param[in]  config  Config.
 *
 * @return 1 if updated in feed, else 0.
 */
int
config_updated_in_feed (config_t config, const gchar *path)
{
  GStatBuf state;
  int last_config_update;

  last_config_update = sql_int ("SELECT modification_time FROM configs"
                                " WHERE id = %llu;",
                                config);

  if (g_stat (path, &state))
    {
      g_warning ("%s: Failed to stat feed config file: %s",
                 __func__,
                 strerror (errno));
      return 0;
    }

  if (state.st_mtime <= last_config_update)
    return 0;

  return 1;
}

/**
 * @brief Update a config from an XML file.
 *
 * @param[in]  config       Existing config.
 * @param[in]  type         New config type.
 * @param[in]  name         New name.
 * @param[in]  comment      New comment.
 * @param[in]  usage_type   New usage type.
 * @param[in]  all_selector  Whether to use "all" selector instead of selectors.
 * @param[in]  selectors     New NVT selectors.
 * @param[in]  preferences   New preferences.
 */
void
update_config (config_t config, const gchar *type, const gchar *name,
               const gchar *comment, const gchar *usage_type,
               int all_selector,
               const array_t* selectors /* nvt_selector_t. */,
               const array_t* preferences /* preference_t. */)
{
  gchar *quoted_name, *quoted_comment, *quoted_type, *actual_usage_type;

  sql_begin_immediate ();

  if (usage_type && strcasecmp (usage_type, "policy") == 0)
    actual_usage_type = "policy";
  else
    actual_usage_type = "scan";

  quoted_name = sql_quote (name);
  quoted_comment = sql_quote (comment ? comment : "");
  quoted_type = sql_quote (type);
  sql ("UPDATE configs"
       " SET name = '%s', comment = '%s', type = '%s', usage_type = '%s',"
       " predefined = 1, modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_name,
       quoted_comment,
       quoted_type,
       actual_usage_type,
       config);
  g_free (quoted_name);
  g_free (quoted_comment);
  g_free (quoted_type);

  /* Replace the NVT selectors. */

  if (type == NULL || strcmp (type, "0") == 0)
    {
      char *selector_uuid;

      if (all_selector)
        selector_uuid = NULL;
      else
        {
          selector_uuid = gvm_uuid_make ();
          if (selector_uuid == NULL)
            {
              g_warning ("%s: failed to allocate UUID", __func__);
              sql_rollback ();
              return;
            }
        }

      sql ("DELETE FROM nvt_selectors"
           " WHERE name != '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
           " AND name = (SELECT nvt_selector FROM configs"
           "             WHERE id = %llu);",
           config);

      sql ("UPDATE configs SET nvt_selector = '%s' WHERE id = %llu;",
           selector_uuid ? selector_uuid : MANAGE_NVT_SELECTOR_UUID_ALL,
           config);

      if (selector_uuid && insert_nvt_selectors (selector_uuid, selectors, 0))
        {
          g_warning ("%s: Error in feed config NVT selector", __func__);
          free (selector_uuid);
          sql_rollback ();
          return;
        }

      free (selector_uuid);
    }

  /* Replace the preferences. */

  sql ("DELETE FROM config_preferences WHERE config = %llu;", config);
  if (config_insert_preferences (config, preferences, type))
    {
      g_warning ("%s: Error in feed config preference", __func__);
      sql_rollback ();
      return;
    }

  sql_commit ();
}

/**
 * @brief Check configs, for startup.
 */
void
check_db_configs ()
{
  migrate_predefined_configs ();

  if (sync_configs_with_feed (FALSE) <= -1)
    g_warning ("%s: Failed to sync configs with feed", __func__);

  /* Warn about feed resources in the trash. */
  if (sql_int ("SELECT EXISTS (SELECT * FROM configs_trash"
               "               WHERE predefined = 1);"))
    {
      g_warning ("%s: There are feed configs/policies in the trash."
                 " These will be excluded from the sync.",
                 __func__);
    }
}

/**
 * @brief Check whole-only families.
 *
 * Called after NVT sync.
 */
void
check_whole_only_in_configs ()
{
  static const gchar *wholes[] = FAMILIES_WHOLE_ONLY;

  for (const gchar **whole = wholes; *whole; whole++)
    {
      gchar *quoted_family;

      quoted_family = sql_quote (*whole);

      /* Delete any excluding NVT selectors. */

      sql ("DELETE FROM nvt_selectors"
           " WHERE type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
           " AND exclude = 1"
           " AND EXISTS (SELECT * FROM nvts"
           "             WHERE oid = family_or_nvt"
           "             AND family = '%s');",
           quoted_family);

      /* Convert any including NVT selectors to family selectors. */

      sql ("WITH sels AS (DELETE FROM nvt_selectors"
           "                     WHERE type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
           "              AND EXISTS (SELECT * FROM nvts"
           "                          WHERE oid = family_or_nvt"
           "                          AND family = '%s')"
           "              RETURNING name),"
           "     names AS (SELECT distinct * FROM sels)"
           " INSERT INTO nvt_selectors"
           " (name, exclude, type, family_or_nvt, family)"
           " SELECT names.name, 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY) ","
           "        '%s', '%s'"
           " FROM names;",
           quoted_family,
           quoted_family,
           quoted_family);

      g_free (quoted_family);
    }
}
