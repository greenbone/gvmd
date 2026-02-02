/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_resources.h"
#include "manage_sql.h"
#include "manage_utils.h"
#include "sql.h"

#include <assert.h>

/**
 * @file
 * @brief GVM management layer: Resources SQL
 *
 * The resources SQL for the GVM management layer.
 */

/**
 * @brief Get the UUID of a resource.
 *
 * @param[in]  type      Type.
 * @param[in]  resource  Resource.
 *
 * @return Freshly allocated UUID on success, else NULL.
 */
gchar *
resource_uuid (const gchar *type, resource_t resource)
{
  assert (valid_db_resource_type (type));

  return sql_string ("SELECT uuid FROM %ss WHERE id = %llu;",
                     type,
                     resource);
}

/**
 * @brief Get the name of a resource.
 *
 * @param[in]  type      Type.
 * @param[in]  uuid      UUID.
 * @param[in]  location  Location.
 * @param[out] name      Return for freshly allocated name.
 *
 * @return 0 success, 1 error in type.
 */
static int
resource_name (const char *type, const char *uuid, int location, char **name)
{
  if (valid_db_resource_type (type) == 0)
    return 1;

  GString *query = g_string_new ("");

  if (strcasecmp (type, "note") == 0)
    {
      g_string_printf (query,
                       "SELECT 'Note for: '"
                       " || (SELECT name"
                       "     FROM nvts"
                       "     WHERE nvts.uuid = tnotes.nvt)"
                       " FROM notes%s AS tnotes"
                       " WHERE uuid = $1;",
                       location == LOCATION_TABLE ? "" : "_trash");

      *name = sql_string_ps (query->str, SQL_STR_PARAM (uuid), NULL);
    }
  else if (strcasecmp (type, "override") == 0)
    {
      g_string_printf (query,
                       "SELECT 'Override for: '"
                       " || (SELECT name"
                       "     FROM nvts"
                       "     WHERE nvts.uuid = tovrr.nvt)"
                       " FROM overrides%s AS tovrr"
                       " WHERE uuid = $1;",
                       location == LOCATION_TABLE ? "" : "_trash");

      *name = sql_string_ps (query->str, SQL_STR_PARAM (uuid), NULL);
    }
  else if (strcasecmp (type, "report") == 0)
    {
      *name = sql_string_ps ("SELECT (SELECT name FROM tasks WHERE id = task)"
                             " || ' - '"
                             " || (SELECT"
                             "       CASE (SELECT end_time FROM tasks"
                             "             WHERE id = task)"
                             "       WHEN 0 THEN 'N/A'"
                             "       ELSE (SELECT iso_time (end_time)"
                             "             FROM tasks WHERE id = task)"
                             "    END)"
                             " FROM reports"
                             " WHERE uuid = $1;",
                             SQL_STR_PARAM (uuid), NULL);
    }
  else if (strcasecmp (type, "result") == 0)
    {
      *name = sql_string_ps ("SELECT (SELECT name FROM tasks WHERE id = task)"
                             " || ' - '"
                             " || (SELECT name FROM nvts WHERE oid = nvt)"
                             " || ' - '"
                             " || (SELECT"
                             "       CASE (SELECT end_time FROM tasks"
                             "             WHERE id = task)"
                             "       WHEN 0 THEN 'N/A'"
                             "       ELSE (SELECT iso_time (end_time)"
                             "             FROM tasks WHERE id = task)"
                             "    END)"
                             " FROM results"
                             " WHERE uuid = $1;",
                             SQL_STR_PARAM (uuid), NULL);
    }
  else if (location == LOCATION_TABLE)
    {
      g_string_printf (query,
                       "SELECT name"
                       " FROM %ss"
                       " WHERE uuid = $1;",
                       type);
      *name = sql_string_ps (query->str, SQL_STR_PARAM (uuid), NULL);
    }
  else if (type_has_trash (type))
    {
      g_string_printf (query,
                       "SELECT name"
                       " FROM %ss%s"
                       " WHERE uuid = $1;",
                       type, strcmp (type, "task") ? "_trash" : "");

      *name = sql_string_ps (query->str, SQL_STR_PARAM (uuid), NULL);
    }
  else
    *name = NULL;

  g_string_free (query, TRUE);
  return 0;
}

/**
 * @brief Get the name of a resource.
 *
 * @param[in]  type      Type.
 * @param[in]  uuid      UUID.
 * @param[out] name      Return for freshly allocated name.
 *
 * @return 0 success, 1 error in type.
 */
int
manage_resource_name (const char *type, const char *uuid, char **name)
{
  return resource_name (type, uuid, LOCATION_TABLE, name);
}

/**
 * @brief Get the name of a trashcan resource.
 *
 * @param[in]  type      Type.
 * @param[in]  uuid      UUID.
 * @param[out] name      Return for freshly allocated name.
 *
 * @return 0 success, 1 error in type.
 */
int
manage_trash_resource_name (const char *type, const char *uuid, char **name)
{
  return resource_name (type, uuid, LOCATION_TRASH, name);
}
