/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_settings.h"
#include "manage_acl.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @file
 * @brief GVM management layer: Settings SQL
 *
 * The Settings SQL for the GVM management layer.
 */

/**
 * @brief Return the uuid of a resource filter from settings.
 *
 * @param[in]  resource  Resource (eg. Filters, Targets, CPE).
 *
 * @return resource filter uuid in settings if it exists, "" otherwise.
 */
char *
setting_filter (const char *resource)
{
  return sql_string ("SELECT value FROM settings WHERE name = '%s Filter'"
                     " AND " ACL_GLOBAL_OR_USER_OWNS () ""
                     " ORDER BY coalesce (owner, 0) DESC;",
                     resource,
                     current_credentials.uuid);
}

/**
 * @brief Return the user's timezone.
 *
 * @return User Severity Class in settings if it exists, else NULL.
 */
char *
setting_timezone ()
{
  return sql_string ("SELECT timezone FROM users WHERE uuid = '%s'",
                     current_credentials.uuid);
}

/**
 * @brief Return the Dynamic Severity user setting as an int.
 *
 * @return 1 if user's Dynamic Severity is "Yes", 0 if it is "No",
 *         or does not exist.
 */
int
setting_dynamic_severity_int ()
{
  return current_credentials.dynamic_severity;
}

/**
 * @brief Count number of settings.
 *
 * @param[in]  filter           Filter term.
 *
 * @return Total number of settings in filtered set.
 */
int
setting_count (const char *filter)
{
  static const char *filter_columns[] = SETTING_ITERATOR_FILTER_COLUMNS;
  static column_t select_columns[] = SETTING_ITERATOR_COLUMNS;
  gchar *clause;
  int ret;

  assert (current_credentials.uuid);

  clause = filter_clause ("setting", filter, filter_columns, select_columns,
                          NULL, 0, 0, NULL, NULL, NULL, NULL, NULL);

  ret = sql_int ("SELECT count (*)"
                 " FROM settings"
                 " WHERE"
                 " (owner = (SELECT id FROM users WHERE uuid = '%s')"
                 "  OR (owner IS NULL"
                 "      AND uuid"
                 "      NOT IN (SELECT uuid FROM settings"
                 "              WHERE owner = (SELECT id FROM users"
                 "                             WHERE uuid = '%s'))))"
                 "%s%s;",
                 current_credentials.uuid,
                 current_credentials.uuid,
                 clause ? " AND " : "",
                 clause ? clause : "");

  g_free (clause);

  return ret;
}

/**
 * @brief Initialise a setting iterator, including observed settings.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  uuid        UUID of setting to limit iteration to.  0 for all.
 * @param[in]  filter      Filter term.
 * @param[in]  first       First setting.
 * @param[in]  max         Maximum number of settings returned.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_setting_iterator (iterator_t *iterator, const char *uuid,
                       const char *filter, int first, int max, int ascending,
                       const char *sort_field)
{
  static const char *filter_columns[] = SETTING_ITERATOR_FILTER_COLUMNS;
  static column_t select_columns[] = SETTING_ITERATOR_COLUMNS;
  gchar *clause, *columns, *quoted_uuid;

  assert (current_credentials.uuid);

  if (first < 0)
    first = 0;
  if (max < 1)
    max = -1;

  clause = filter_clause ("setting", filter, filter_columns, select_columns,
                          NULL, 0, 0, NULL, NULL, NULL, NULL, NULL);

  quoted_uuid = uuid ? sql_quote (uuid) : NULL;
  columns = columns_build_select (select_columns);

  if (quoted_uuid)
    init_iterator (iterator,
                   "SELECT %s"
                   " FROM settings"
                   " WHERE uuid = '%s'"
                   " AND (owner = (SELECT id FROM users WHERE uuid = '%s')"
                   "      OR (owner IS NULL"
                   "          AND uuid"
                   "          NOT IN (SELECT uuid FROM settings"
                   "                  WHERE owner = (SELECT id FROM users"
                   "                                 WHERE uuid = '%s'))))",
                   columns,
                   quoted_uuid,
                   current_credentials.uuid,
                   current_credentials.uuid);
  else
    init_iterator (iterator,
                   "SELECT %s"
                   " FROM settings"
                   " WHERE"
                   " (owner = (SELECT id FROM users WHERE uuid = '%s')"
                   "  OR (owner IS NULL"
                   "      AND uuid"
                   "      NOT IN (SELECT uuid FROM settings"
                   "              WHERE owner = (SELECT id FROM users"
                   "                             WHERE uuid = '%s'))))"
                   "%s%s"
                   " ORDER BY %s %s"
                   " LIMIT %s OFFSET %i;",
                   columns,
                   current_credentials.uuid,
                   current_credentials.uuid,
                   clause ? " AND " : "",
                   clause ? clause : "",
                   sort_field ? sort_field : "id",
                   ascending ? "ASC" : "DESC",
                   sql_select_limit (max),
                   first);

  g_free (quoted_uuid);
  g_free (columns);
  g_free (clause);
}

/**
 * @brief Get the UUID from a setting iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The UUID of the setting, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (setting_iterator_uuid, 1);

/**
 * @brief Get the name from a setting iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the setting, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (setting_iterator_name, 2);

/**
 * @brief Get the comment from a setting iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The comment of the setting, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (setting_iterator_comment, 3);

/**
 * @brief Get the value from a setting iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the setting, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (setting_iterator_value, 4);
