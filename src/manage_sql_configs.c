/* GVM
 * $Id$
 * Description: GVM management layer SQL: Configs.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2019 Greenbone Networks GmbH
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
 * @file manage_sql_configs.c
 * @brief GVM management layer: Config SQL
 *
 * The Config SQL for the GVM management layer.
 */

#include "manage_configs.h"
#include "sql.h"

#include <stdlib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


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
 *      includes in all other families.
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

  /* The number of families can only grow if there is selector that includes
   * all. */

  quoted_selector = sql_quote (selector);
#if 0
  ret = sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                 " WHERE name = '%s'"
                 " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                 " AND exclude = 0"
                 " LIMIT 1;",
                 quoted_selector);
  g_free (quoted_selector);
  return ret;
#else
  char *string;
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
#endif
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
  init_iterator (iterator, sql);
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
 *                       If \param family is NULL, true if the the families
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
 *
 * @return 0 success, -1 error.
 */
static void
nvt_selector_remove (const char* quoted_selector,
                     const char* quoted_family,
                     int type)
{
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
 *
 * @return 0 success, -1 error.
 */
static void
nvt_selector_remove_selector (const char* quoted_selector,
                              const char* family_or_nvt,
                              int type)
{
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
 *
 * @return 0 success, -1 error.
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
 *
 * @return 0 success, -1 error.
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
 * @brief Refresh NVT selection of a config from given families.
 *
 * @param[in]  config_id             Config.
 * @param[in]  growing_all_families  Growing families with all selection.
 * @param[in]  static_all_families   Static families with all selection.
 * @param[in]  growing_families      The rest of the growing families.
 * @param[in]  grow_families         1 if families should grow, else 0.
 *
 * @return 0 success, 1 config in use, 2 failed to find config, -1 error.
 */
int
manage_set_config_families (const gchar *config_id,
                            GPtrArray* growing_all_families,
                            GPtrArray* static_all_families,
                            GPtrArray* growing_families,
                            int grow_families)
{
  config_t config;
  iterator_t families;
  gchar *quoted_selector;
  int constraining;
  char *selector;

  sql_begin_immediate ();

  if (find_config_with_permission (config_id, &config, "modify_config"))
    {
      sql_rollback ();
      return -1;
    }
  if (config == 0)
    {
      sql_rollback ();
      return 2;
    }

  if (sql_int ("SELECT count(*) FROM tasks"
               " WHERE config = %llu AND hidden = 0;",
               config))
    {
      sql_rollback ();
      return 1;
    }

  if (config_type (config) > 0)
    {
      sql_rollback ();
      return 0;
    }
  constraining = config_families_growing (config);

  if (constraining + grow_families == 1)
    {
      if (switch_representation (config, constraining))
        {
          sql_rollback ();
          return -1;
        }
      constraining = constraining == 0;
    }

  selector = config_nvt_selector (config);
  if (selector == NULL)
    {
      /* The config should always have a selector. */
      sql_rollback ();
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

  sql_commit ();

  g_free (quoted_selector);
  free (selector);
  return 0;
}

/**
 * @brief Insert NVT selectors.
 *
 * @param[in]  quoted_name  Name of NVT selector.
 * @param[in]  selectors    NVT selectors.
 *
 * @return 0 success, -1 error, -3 input error.
 */
static int
insert_nvt_selectors (const char *quoted_name,
                      const array_t* selectors /* nvt_selector_t. */)
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
          nvti_t *nvti = nvtis_lookup (nvti_cache, selector->family_or_nvt);

          /* An NVT selector. */

          if (nvti)
            {
              family = nvti_family (nvti);

              if (family == NULL)
                {
                  g_warning ("%s: skipping NVT '%s' from import of config '%s'"
                             " because the NVT is missing a family in the"
                             " cache",
                             __FUNCTION__,
                             selector->family_or_nvt,
                             quoted_name);
                  continue;
                }
            }
          else
            {
              g_warning ("%s: skipping NVT '%s' from import of config '%s'"
                         " because the NVT is missing from the cache",
                         __FUNCTION__,
                         selector->family_or_nvt,
                         quoted_name);
              continue;
            }

          quoted_family_or_nvt = sql_quote (selector->family_or_nvt);
          quoted_family = sql_quote (family);
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
                         __FUNCTION__,
                         selector->family_or_nvt,
                         quoted_name);
              continue;
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
                         __FUNCTION__,
                         quoted_name);
              continue;
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
      g_warning ("%s: Failed to get config selector", __FUNCTION__);
      return -1;
    }
  quoted_selector = sql_quote (selector);

  constraining = config_families_growing (config);

  g_debug ("%s: Updating NVT family for selector '%s'", __FUNCTION__, selector);

  if (constraining)
    {
      /* Constraining the universe. */

      g_debug ("%s:   Selector constrains universe", __FUNCTION__);

      if (nvt_selector_family_growing (selector, old_family, constraining))
        {
          /* Old family is growing. */

          g_debug ("%s:   Old family is growing", __FUNCTION__);

          if (nvt_selector_has (quoted_selector, oid, NVT_SELECTOR_TYPE_NVT,
                                0 /* Included. */))
            {
              /* NVT explicitly included in old family, which is redundant, so
               * drop selector. */
              g_debug ("%s:   Drop selector", __FUNCTION__);
              nvt_selector_remove_selector (quoted_selector,
                                            oid,
                                            NVT_SELECTOR_TYPE_NVT);
            }
          else if (nvt_selector_has (quoted_selector, oid,
                                     NVT_SELECTOR_TYPE_NVT,
                                     1 /* Excluded. */))
            {
              /* NVT explicitly excluded from old family. */

              g_debug ("%s:   NVT excluded from old family", __FUNCTION__);

              if (nvt_selector_family_growing (selector, new_family,
                                               constraining))
                {
                  /* New family is growing, change NVT to new family. */
                  g_debug ("%s:   Change family", __FUNCTION__);
                  nvt_selector_set_family (quoted_selector,
                                           oid,
                                           NVT_SELECTOR_TYPE_NVT,
                                           new_family);
                }
              else
                {
                  /* New family static, NVT excluded already, so drop NVT
                   * selector. */
                  g_debug ("%s:   Remove selector", __FUNCTION__);
                  nvt_selector_remove_selector (quoted_selector,
                                                oid,
                                                NVT_SELECTOR_TYPE_NVT);
                }
            }
        }
      else
        {
          /* Old family is static. */

          g_debug ("%s:   Old family is static", __FUNCTION__);

          if (nvt_selector_has (quoted_selector, oid, NVT_SELECTOR_TYPE_NVT,
                                0 /* Included. */))
            {
              /* NVT explicitly included in old family. */

              g_debug ("%s:   NVT included in old family", __FUNCTION__);

              if (nvt_selector_family_growing (selector, new_family,
                                               constraining))
                {
                  /* New family is growing so it already includes the NVT.
                   * Remove the NVT selector. */
                  g_debug ("%s:   Remove selector", __FUNCTION__);
                  nvt_selector_remove_selector (quoted_selector,
                                                oid,
                                                NVT_SELECTOR_TYPE_NVT);
                }
              else
                {
                  /* New family static, change NVT to new family. */
                  g_debug ("%s:   Change family", __FUNCTION__);
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
              g_debug ("%s:   Remove selector", __FUNCTION__);
              nvt_selector_remove_selector (quoted_selector,
                                            oid,
                                            NVT_SELECTOR_TYPE_NVT);
            }
        }
    }
  else
    {
      /* Generating from empty. */

      g_debug ("%s:   Selector generates from empty", __FUNCTION__);

      if (nvt_selector_family_growing (selector, old_family, constraining))
        {
          /* Old family is growing. */

          g_debug ("%s:   Old family is growing", __FUNCTION__);

          if (nvt_selector_has (quoted_selector, oid, NVT_SELECTOR_TYPE_NVT,
                                0 /* Included. */))
            {
              /* NVT explicitly included in old family.  This is redundant, so
               * just remove the NVT selector. */
              g_debug ("%s:   Remove selector", __FUNCTION__);
              nvt_selector_remove_selector (quoted_selector,
                                            oid,
                                            NVT_SELECTOR_TYPE_NVT);
            }
          else if (nvt_selector_has (quoted_selector, oid,
                                     NVT_SELECTOR_TYPE_NVT,
                                     1 /* Excluded. */))
            {
              /* NVT explicitly excluded from old family. */

              g_debug ("%s:   NVT excluded from old family", __FUNCTION__);

              if (nvt_selector_family_growing (selector, new_family,
                                               constraining))
                {
                  /* New family is growing, change NVT to new family. */
                  g_debug ("%s:   Change family", __FUNCTION__);
                  nvt_selector_set_family (quoted_selector,
                                           oid,
                                           NVT_SELECTOR_TYPE_NVT,
                                           new_family);
                }
              else
                {
                  /* New family static, so the NVT is already excluded from the
                   * new family.  Remove the NVT selector. */
                  g_debug ("%s:   Remove selector", __FUNCTION__);
                  nvt_selector_remove_selector (quoted_selector,
                                                oid,
                                                NVT_SELECTOR_TYPE_NVT);
                }
            }
        }
      else
        {
          /* Old family is static. */

          g_debug ("%s:   Old family is static", __FUNCTION__);

          if (nvt_selector_has (quoted_selector, oid, NVT_SELECTOR_TYPE_NVT,
                                0 /* Included. */))
            {
              /* NVT explicitly included in old family. */

              g_debug ("%s:   NVT included in old family", __FUNCTION__);

              if (nvt_selector_family_growing (selector, new_family,
                                               constraining))
                {
                  /* New family growing, so the NVT is already in there.  Remove
                   * the NVT selector. */
                  g_debug ("%s:   Remove selector", __FUNCTION__);
                  nvt_selector_remove_selector (quoted_selector,
                                                oid,
                                                NVT_SELECTOR_TYPE_NVT);
                }
              else
                {
                  /* New family is static, change NVT to new family. */
                  g_debug ("%s:   Change family", __FUNCTION__);
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
                       __FUNCTION__);
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
 * @brief Add an NVT preference.
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
        {
          g_warning ("%s: preference '%s' already exists",
                     __FUNCTION__, name);
        }
      else
        {
          sql ("INSERT into nvt_preferences (name, value)"
               " VALUES ('%s', '%s');",
               quoted_name, quoted_value);
        }
    }

  g_free (quoted_name);
  g_free (quoted_value);
}

/**
 * @brief Enable the NVT preferences.
 */
void
manage_nvt_preferences_enable ()
{
  sql ("DELETE FROM %s.meta WHERE name = 'nvt_preferences_enabled';",
       sql_schema ());
  sql ("INSERT INTO %s.meta (name, value)"
       " VALUES ('nvt_preferences_enabled', 1);",
       sql_schema ());
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
