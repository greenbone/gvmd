/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_resources.h"
#include "manage_acl.h"
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

/* TODO Only used by find_scanner, find_permission and check_permission_args. */
/**
 * @brief Find a resource given a UUID.
 *
 * This only looks for resources owned (or effectively owned) by the current user.
 * So no shared resources and no globals.
 *
 * @param[in]   type       Type of resource.
 * @param[in]   uuid       UUID of resource.
 * @param[out]  resource   Resource return, 0 if successfully failed to find resource.
 *
 * @return FALSE on success (including if failed to find resource), TRUE on error.
 */
gboolean
find_resource (const char* type, const char* uuid, resource_t* resource)
{
  gchar *quoted_uuid;
  quoted_uuid = sql_quote (uuid);
  if (acl_user_owns_uuid (type, quoted_uuid, 0) == 0)
    {
      g_free (quoted_uuid);
      *resource = 0;
      return FALSE;
    }
  // TODO should really check type
  switch (sql_int64 (resource,
                     "SELECT id FROM %ss WHERE uuid = '%s'%s;",
                     type,
                     quoted_uuid,
                     strcmp (type, "task") ? "" : " AND hidden < 2"))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *resource = 0;
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
 * @brief Find a resource given a UUID.
 *
 * @param[in]   type       Type of resource.
 * @param[in]   uuid       UUID of resource.
 * @param[out]  resource   Resource return, 0 if successfully failed to find resource.
 *
 * @return FALSE on success (including if failed to find resource), TRUE on error.
 */
gboolean
find_resource_no_acl (const char* type, const char* uuid, resource_t* resource)
{
  gchar *quoted_uuid;
  quoted_uuid = sql_quote (uuid);

  // TODO should really check type
  switch (sql_int64 (resource,
                     "SELECT id FROM %ss WHERE uuid = '%s'%s;",
                     type,
                     quoted_uuid,
                     strcmp (type, "task") ? "" : " AND hidden < 2"))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *resource = 0;
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
 * @brief Find a resource given a UUID and a permission.
 *
 * @param[in]   type        Type of resource.
 * @param[in]   uuid        UUID of resource.
 * @param[out]  resource    Resource return, 0 if successfully failed to find
 *                          resource.
 * @param[in]   permission  Permission.
 * @param[in]   trash       Whether resource is in trashcan.
 *
 * @return FALSE on success (including if failed to find resource), TRUE on
 *         error.
 */
gboolean
find_resource_with_permission (const char* type, const char* uuid,
                               resource_t* resource, const char *permission,
                               int trash)
{
  gchar *quoted_uuid;
  if (uuid == NULL)
    return TRUE;
  if ((type == NULL) || (valid_db_resource_type (type) == 0))
    return TRUE;
  quoted_uuid = sql_quote (uuid);
  if (acl_user_has_access_uuid (type, quoted_uuid, permission, trash) == 0)
    {
      g_free (quoted_uuid);
      *resource = 0;
      return FALSE;
    }
  switch (sql_int64 (resource,
                     "SELECT id FROM %ss%s WHERE uuid = '%s'%s%s;",
                     type,
                     (trash && strcmp (type, "task") && strcmp (type, "report"))
                      ? "_trash"
                      : "",
                     quoted_uuid,
                     strcmp (type, "task")
                      ? ""
                      : (trash ? " AND hidden = 2" : " AND hidden < 2"),
                     strcmp (type, "report")
                      ? ""
                      : (trash
                          ? " AND (SELECT hidden FROM tasks"
                            "      WHERE tasks.id = task)"
                            "     = 2"
                          : " AND (SELECT hidden FROM tasks"
                          "        WHERE tasks.id = task)"
                          "       = 0")))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *resource = 0;
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
 * @brief Find a resource given a name.
 *
 * @param[in]   type      Type of resource.
 * @param[in]   name      A resource name.
 * @param[out]  resource  Resource return, 0 if successfully failed to find
 *                        resource.
 *
 * @return FALSE on success (including if failed to find resource), TRUE on
 *         error.
 */
gboolean
find_resource_by_name (const char* type, const char* name, resource_t *resource)
{
  gchar *quoted_name;
  quoted_name = sql_quote (name);
  // TODO should really check type
  switch (sql_int64 (resource,
                     "SELECT id FROM %ss WHERE name = '%s'"
                     " ORDER BY id DESC;",
                     type,
                     quoted_name))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *resource = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_name);
        return TRUE;
        break;
    }

  g_free (quoted_name);
  return FALSE;
}

/**
 * @brief Find a resource given a UUID and a permission.
 *
 * @param[in]   type        Type of resource.
 * @param[in]   name        Name of resource.
 * @param[out]  resource    Resource return, 0 if successfully failed to find
 *                          resource.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find resource), TRUE on
 *         error.
 */
gboolean
find_resource_by_name_with_permission (const char *type, const char *name,
                                       resource_t *resource,
                                       const char *permission)
{
  gchar *quoted_name;
  assert (strcmp (type, "task"));
  if (name == NULL)
    return TRUE;
  quoted_name = sql_quote (name);
  // TODO should really check type
  switch (sql_int64 (resource,
                     "SELECT id FROM %ss WHERE name = '%s'"
                     " ORDER BY id DESC;",
                     type,
                     quoted_name))
    {
      case 0:
        {
          gchar *uuid;

          uuid = sql_string ("SELECT uuid FROM %ss WHERE id = %llu;",
                             type, *resource);
          if (acl_user_has_access_uuid (type, uuid, permission, 0) == 0)
            {
              g_free (uuid);
              g_free (quoted_name);
              *resource = 0;
              return FALSE;
            }
          g_free (uuid);
        }
        break;
      case 1:        /* Too few rows in result of query. */
        *resource = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_name);
        return TRUE;
        break;
    }

  g_free (quoted_name);
  return FALSE;
}
