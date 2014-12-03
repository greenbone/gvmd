/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: Access Control "Layer".
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
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
 * @file  manage_acl.c
 * @brief The OpenVAS Manager management library (Access Control Layer).
 *
 * This file isolates the access control portions of the OpenVAS manager
 * management library.
 */

#include "manage_acl.h"
#include "manage_sql.h"
#include "sql.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Test whether a user may perform an operation.
 *
 * @param[in]  operation  Name of operation.
 *
 * @return 1 if user has permission, else 0.
 */
int
user_may (const char *operation)
{
  int ret;
  gchar *quoted_operation;

  assert (current_credentials.uuid);
  assert (operation);

  if (strlen (current_credentials.uuid) == 0)
    /* Allow the dummy user in init_manage to do anything. */
    return 1;

  if (sql_int ("SELECT user_can_everything ('%s');",
               current_credentials.uuid))
    return 1;

  quoted_operation = sql_quote (operation);

  ret = sql_int (USER_MAY ("0"),
                 current_credentials.uuid,
                 current_credentials.uuid,
                 current_credentials.uuid,
                 quoted_operation,
                 quoted_operation,
                 quoted_operation,
                 quoted_operation);

  g_free (quoted_operation);

  return ret;
}

/**
 * @brief Test whether a user may perform any operation.
 *
 * @param[in]  user_id  UUID of user.
 *
 * @return 1 if user has permission, else 0.
 */
int
user_can_everything (const char *user_id)
{
  return sql_int ("SELECT count(*) > 0 FROM permissions"
                  " WHERE resource = 0"
                  " AND ((subject_type = 'user'"
                  "       AND subject"
                  "           = (SELECT id FROM users"
                  "              WHERE users.uuid = '%s'))"
                  "      OR (subject_type = 'group'"
                  "          AND subject"
                  "              IN (SELECT DISTINCT \"group\""
                  "                  FROM group_users"
                  "                  WHERE \"user\" = (SELECT id"
                  "                                    FROM users"
                  "                                    WHERE users.uuid"
                  "                                          = '%s')))"
                  "      OR (subject_type = 'role'"
                  "          AND subject"
                  "              IN (SELECT DISTINCT role"
                  "                  FROM role_users"
                  "                  WHERE \"user\" = (SELECT id"
                  "                                    FROM users"
                  "                                    WHERE users.uuid"
                  "                                          = '%s'))))"
                  " AND name = 'Everything';",
                  user_id,
                  user_id,
                  user_id);
}

/**
 * @brief Test whether a user has super permission on another user.
 *
 * @param[in]  super_user_id  UUID of user who may have super permission.
 * @param[in]  other_user     Other user.
 *
 * @return 1 if user has permission, else 0.
 */
int
user_has_super (const char *super_user_id, user_t other_user)
{
  if (sql_int (" SELECT EXISTS (SELECT * FROM permissions"
               "                WHERE name = 'Super'"
               /*                    Super on everyone. */
               "                AND ((resource = 0)"
               /*                    Super on other_user. */
               "                     OR ((resource_type = 'user')"
               "                         AND (resource = %llu))"
               /*                    Super on other_user's role. */
               "                     OR ((resource_type = 'role')"
               "                         AND (resource"
               "                              IN (SELECT DISTINCT role"
               "                                  FROM role_users"
               "                                  WHERE \"user\" = %llu)))"
               /*                    Super on other_user's group. */
               "                     OR ((resource_type = 'group')"
               "                         AND (resource"
               "                              IN (SELECT DISTINCT \"group\""
               "                                  FROM group_users"
               "                                  WHERE \"user\" = %llu))))"
               "                AND ((subject_type = 'user'"
               "                      AND subject"
               "                          = (SELECT id FROM users"
               "                             WHERE users.uuid = '%s'))"
               "                     OR (subject_type = 'group'"
               "                         AND subject"
               "                             IN (SELECT DISTINCT \"group\""
               "                                 FROM group_users"
               "                                 WHERE \"user\""
               "                                       = (SELECT id"
               "                                          FROM users"
               "                                          WHERE users.uuid"
               "                                                = '%s')))"
               "                     OR (subject_type = 'role'"
               "                         AND subject"
               "                             IN (SELECT DISTINCT role"
               "                                 FROM role_users"
               "                                 WHERE \"user\""
               "                                       = (SELECT id"
               "                                          FROM users"
               "                                          WHERE users.uuid"
               "                                                = '%s')))));",
               other_user,
               other_user,
               other_user,
               super_user_id,
               super_user_id,
               super_user_id))
    return 1;
  return 0;
}

/**
 * @brief Check whether a user is an Admin.
 *
 * @param[in]  uuid  Uuid of user.
 *
 * @return 1 if user is an Admin, else 0.
 */
int
user_is_admin (const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count (*) FROM role_users"
                 " WHERE role = (SELECT id FROM roles"
                 "               WHERE uuid = '" ROLE_UUID_ADMIN "')"
                 " AND \"user\" = (SELECT id FROM users WHERE uuid = '%s');",
                 quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

/**
 * @brief Check whether a user is an Observer.
 *
 * @param[in]  uuid  Uuid of user.
 *
 * @return 1 if user is an Observer, else 0.
 */
int
user_is_observer (const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count (*) FROM role_users"
                 " WHERE role = (SELECT id FROM roles"
                 "               WHERE uuid = '" ROLE_UUID_OBSERVER "')"
                 " AND \"user\" = (SELECT id FROM users WHERE uuid = '%s');",
                 quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

/**
 * @brief Check whether a user is a Super Admin.
 *
 * @param[in]  uuid  Uuid of user.
 *
 * @return 1 if user is a Super Admin, else 0.
 */
int
user_is_super_admin (const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count (*) FROM role_users"
                 " WHERE role = (SELECT id FROM roles"
                 "               WHERE uuid = '" ROLE_UUID_SUPER_ADMIN "')"
                 " AND \"user\" = (SELECT id FROM users WHERE uuid = '%s');",
                 quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

/**
 * @brief Check whether a user has the User role.
 *
 * @param[in]  uuid  Uuid of user.
 *
 * @return 1 if user has the User role, else 0.
 */
int
user_is_user (const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count (*) FROM role_users"
                 " WHERE role = (SELECT id FROM roles"
                 "               WHERE uuid = '" ROLE_UUID_USER "')"
                 " AND \"user\" = (SELECT id FROM users WHERE uuid = '%s');",
                 quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

/**
 * @brief Test whether a user owns a result.
 *
 * @param[in]  uuid      UUID of result.
 *
 * @return 1 if user owns result, else 0.
 */
int
user_owns_result (const char *uuid)
{
  int ret;

  assert (current_credentials.uuid);

  ret = sql_int ("SELECT count(*) FROM results, reports"
                 " WHERE results.uuid = '%s'"
                 " AND results.report = reports.id"
                 " AND ((reports.owner IS NULL) OR (reports.owner ="
                 " (SELECT users.id FROM users WHERE users.uuid = '%s')));",
                 uuid,
                 current_credentials.uuid);

  return ret;
}

/**
 * @brief Test whether a user owns a resource.
 *
 * @param[in]  type  Type of resource, for example "task".
 * @param[in]  uuid      UUID of resource.
 * @param[in]  trash     Whether the resource is in the trash.
 *
 * @return 1 if user owns resource, else 0.
 */
int
user_owns_uuid (const char *type, const char *uuid, int trash)
{
  int ret;

  assert (current_credentials.uuid);

  if (sql_int (/* The user has super permission on everyone. */
               " SELECT EXISTS (SELECT * FROM permissions"
               "                WHERE name = 'Super'"
               /*                    Super on everyone. */
               "                AND ((resource = 0)"
               /*                    Super on other_user. */
               "                     OR ((resource_type = 'user')"
               "                         AND (resource = (SELECT %ss.owner"
               "                                          FROM %ss"
               "                                          WHERE uuid = '%s')))"
               /*                    Super on other_user's role. */
               "                     OR ((resource_type = 'role')"
               "                         AND (resource"
               "                              IN (SELECT DISTINCT role"
               "                                  FROM role_users"
               "                                  WHERE \"user\""
               "                                        = (SELECT %ss.owner"
               "                                           FROM %ss"
               "                                           WHERE uuid"
               "                                                 = '%s'))))"
               /*                    Super on other_user's group. */
               "                     OR ((resource_type = 'group')"
               "                         AND (resource"
               "                              IN (SELECT DISTINCT \"group\""
               "                                  FROM group_users"
               "                                  WHERE \"user\""
               "                                        = (SELECT %ss.owner"
               "                                           FROM %ss"
               "                                           WHERE uuid"
               "                                                 = '%s')))))"
               "                AND ((subject_type = 'user'"
               "                      AND subject"
               "                          = (SELECT id FROM users"
               "                             WHERE users.uuid = '%s'))"
               "                     OR (subject_type = 'group'"
               "                         AND subject"
               "                             IN (SELECT DISTINCT \"group\""
               "                                 FROM group_users"
               "                                 WHERE \"user\""
               "                                       = (SELECT id"
               "                                          FROM users"
               "                                          WHERE users.uuid"
               "                                                = '%s')))"
               "                     OR (subject_type = 'role'"
               "                         AND subject"
               "                             IN (SELECT DISTINCT role"
               "                                 FROM role_users"
               "                                 WHERE \"user\""
               "                                       = (SELECT id"
               "                                          FROM users"
               "                                          WHERE users.uuid"
               "                                                = '%s')))));",
               type,
               type,
               uuid,
               type,
               type,
               uuid,
               type,
               type,
               uuid,
               current_credentials.uuid,
               current_credentials.uuid,
               current_credentials.uuid))
    return 1;

  if (strcmp (type, "result") == 0)
    return user_owns_result (uuid);
  if ((strcmp (type, "nvt") == 0)
      || (strcmp (type, "cve") == 0)
      || (strcmp (type, "cpe") == 0)
      || (strcmp (type, "ovaldef") == 0)
      || (strcmp (type, "cert_bund_adv") == 0)
      || (strcmp (type, "dfn_cert_adv") == 0))
    return 1;

  ret = sql_int ("SELECT count(*) FROM %ss%s"
                 " WHERE uuid = '%s'"
                 "%s"
                 " AND ((owner IS NULL) OR (owner ="
                 " (SELECT users.id FROM users WHERE users.uuid = '%s')));",
                 type,
                 (strcmp (type, "task") && trash) ? "_trash" : "",
                 uuid,
                 (strcmp (type, "task")
                   ? ""
                   : (trash ? " AND hidden = 2" : " AND hidden < 2")),
                 current_credentials.uuid);

  return ret;
}

/**
 * @brief Test whether the user may access a resource.
 *
 * @param[in]  type      Type of resource, for example "task".
 * @param[in]  uuid      UUID of resource.
 * @param[in]  permission       Permission.
 * @param[in]  trash            Whether the resource is in the trash.
 *
 * @return 1 if user may access resource, else 0.
 */
int
user_has_access_uuid (const char *type, const char *uuid,
                      const char *permission, int trash)
{
  int ret, get;
  char *uuid_task;
  gchar *quoted_permission;

  assert (current_credentials.uuid);

  if (!strcmp (current_credentials.uuid,  ""))
    return 1;

  // FIX or super
  ret = user_owns_uuid (type, uuid, trash);
  if (ret)
    return ret;

  if (trash)
    /* For simplicity, trashcan items are visible only to their owners. */
    return 0;

  if (strcasecmp (type, "report") == 0)
    {
      task_t task;
      report_t report;

      switch (sql_int64 (&report,
                         "SELECT id FROM reports WHERE uuid = '%s';",
                         uuid))
        {
          case 0:
            break;
          case 1:        /* Too few rows in result of query. */
            return 0;
            break;
          default:       /* Programming error. */
            assert (0);
          case -1:
            return 0;
            break;
        }

      report_task (report, &task);
      if (task == 0)
        return 0;
      task_uuid (task, &uuid_task);
    }
  else if (strcasecmp (type, "result") == 0)
    {
      task_t task;

      switch (sql_int64 (&task,
                         "SELECT task FROM results WHERE uuid = '%s';",
                         uuid))
        {
          case 0:
            break;
          case 1:        /* Too few rows in result of query. */
            return 0;
            break;
          default:       /* Programming error. */
            assert (0);
          case -1:
            return 0;
            break;
        }

      task_uuid (task, &uuid_task);
    }
  else
    uuid_task = NULL;

  if ((strcmp (type, "permission") == 0)
      && ((permission == NULL)
          || (strlen (permission) > 3 && strncmp (permission, "get", 3) == 0)))
    {
      ret = sql_int ("SELECT count(*) FROM permissions"
                     /* Any permission implies 'get'. */
                     " WHERE (resource_uuid = '%s'"
                     /* Users may view any permissions that affect them. */
                     "        OR uuid = '%s')"
                     " AND ((subject_type = 'user'"
                     "       AND subject"
                     "           = (SELECT id FROM users"
                     "              WHERE users.uuid = '%s'))"
                     "      OR (subject_type = 'group'"
                     "          AND subject"
                     "              IN (SELECT DISTINCT \"group\""
                     "                  FROM group_users"
                     "                  WHERE \"user\" = (SELECT id"
                     "                                    FROM users"
                     "                                    WHERE users.uuid"
                     "                                          = '%s')))"
                     "      OR (subject_type = 'role'"
                     "          AND subject"
                     "              IN (SELECT DISTINCT role"
                     "                  FROM role_users"
                     "                  WHERE \"user\" = (SELECT id"
                     "                                    FROM users"
                     "                                    WHERE users.uuid"
                     "                                          = '%s'))));",
                     uuid_task ? uuid_task : uuid,
                     uuid_task ? uuid_task : uuid,
                     current_credentials.uuid,
                     current_credentials.uuid,
                     current_credentials.uuid);
      free (uuid_task);
      return ret;
    }
  else if (strcmp (type, "permission") == 0)
    {
      /* Only Admins can modify, delete, etc other users' permissions.
       * This only really affects higher level permissions, because that's
       * all Admins can see of others' permissions. */
      free (uuid_task);
      return user_can_everything (current_credentials.uuid);
    }

  get = (permission == NULL
         || (strlen (permission) > 3 && strncmp (permission, "get", 3) == 0));
  quoted_permission = sql_quote (permission ? permission : "");

  ret = sql_int ("SELECT count(*) FROM permissions"
                 " WHERE resource_uuid = '%s'"
                 " AND ((subject_type = 'user'"
                 "       AND subject"
                 "           = (SELECT id FROM users"
                 "              WHERE users.uuid = '%s'))"
                 "      OR (subject_type = 'group'"
                 "          AND subject"
                 "              IN (SELECT DISTINCT \"group\""
                 "                  FROM group_users"
                 "                  WHERE \"user\" = (SELECT id"
                 "                                    FROM users"
                 "                                    WHERE users.uuid"
                 "                                          = '%s')))"
                 "      OR (subject_type = 'role'"
                 "          AND subject"
                 "              IN (SELECT DISTINCT role"
                 "                  FROM role_users"
                 "                  WHERE \"user\" = (SELECT id"
                 "                                    FROM users"
                 "                                    WHERE users.uuid"
                 "                                          = '%s'))))"
                 " %s%s%s;",
                 uuid_task ? uuid_task : uuid,
                 current_credentials.uuid,
                 current_credentials.uuid,
                 current_credentials.uuid,
                 (get ? "" : "AND name = '"),
                 (get ? "" : quoted_permission),
                 (get ? "" : "'"));

  free (uuid_task);
  g_free (quoted_permission);
  return ret;
}

/**
 * @brief Check whether a type has permission support.
 *
 * @param[in]  type          Type of resource.
 *
 * @return 1 yes, 0 no.
 */
static int
type_has_permissions (const char *type)
{
  return 1;
}

/**
 * @brief Check whether a type has permission support.
 *
 * @param[in]  type          Type of resource.
 *
 * @return 1 yes, 0 no.
 */
static int
type_is_shared (const char *type)
{
  return 0;
}

/**
 * @brief FIX Initialise a target iterator, limited to the current user's targets.
 *
 * @param[in]  type            Type of resource.
 * @param[in]  get             GET data.
 * @param[in]  owned           Only get items owned by the current user.
 * @param[in]  owner_filter    Owner filter keyword.
 * @param[in]  resource        Resource.
 * @param[in]  permissions     Permissions.
 *
 * @return Newly allocated owned clause.
 */
gchar *
where_owned (const char *type, const get_data_t *get, int owned,
             const gchar *owner_filter, resource_t resource,
             array_t *permissions)
{
  gchar *owned_clause;

  if (owned)
    {
      gchar *permission_clause, *filter_owned_clause;
      GString *permission_or;
      int index;

      permission_or = g_string_new ("");
      index = 0;
      if (permissions)
        for (; index < permissions->len; index++)
          {
            gchar *permission;
            permission = (gchar*) g_ptr_array_index (permissions, index);
            if (strcasecmp (permission, "any") == 0)
              {
                g_string_free (permission_or, TRUE);
                permission_or = g_string_new ("t ()");
                index = 1;
                break;
              }
            if (index == 0)
              g_string_append_printf (permission_or, "name = '%s'", permission);
            else
              g_string_append_printf (permission_or, " OR name = '%s'",
                                      permission);
          }

      /* Check on index is because default is owner and global, for backward
       * compatibility. */
      if (current_credentials.uuid && index)
        {
          gchar *clause;
          clause
           = g_strdup_printf ("OR EXISTS"
                              " (SELECT id FROM permissions"
                              "  WHERE resource = %ss%s.id"
                              "  AND resource_type = '%s'"
                              "  AND resource_location = %i"
                              "  AND ((subject_type = 'user'"
                              "        AND subject"
                              "            = (SELECT id FROM users"
                              "               WHERE users.uuid = '%s'))"
                              "       OR (subject_type = 'group'"
                              "           AND subject"
                              "               IN (SELECT DISTINCT \"group\""
                              "                   FROM group_users"
                              "                   WHERE \"user\""
                              "                         = (SELECT id"
                              "                            FROM users"
                              "                            WHERE users.uuid"
                              "                                  = '%s')))"
                              "       OR (subject_type = 'role'"
                              "           AND subject"
                              "               IN (SELECT DISTINCT role"
                              "                   FROM role_users"
                              "                   WHERE \"user\""
                              "                         = (SELECT id"
                              "                            FROM users"
                              "                            WHERE users.uuid"
                              "                                  = '%s'))))"
                              "  AND (%s))",
                              type,
                              get->trash && strcmp (type, "task") ? "_trash" : "",
                              type,
                              get->trash ? LOCATION_TRASH : LOCATION_TABLE,
                              current_credentials.uuid,
                              current_credentials.uuid,
                              current_credentials.uuid,
                              permission_or->str);

          if (strcmp (type, "report") == 0)
            permission_clause
             = g_strdup_printf ("%s"
                                " OR EXISTS"
                                " (SELECT id FROM permissions"
                                "  WHERE resource = reports%s.task"
                                "  AND resource_type = 'task'"
                                "  AND ((subject_type = 'user'"
                                "        AND subject"
                                "            = (SELECT id FROM users"
                                "               WHERE users.uuid = '%s'))"
                                "       OR (subject_type = 'group'"
                                "           AND subject"
                                "               IN (SELECT DISTINCT \"group\""
                                "                   FROM group_users"
                                "                   WHERE \"user\""
                                "                         = (SELECT id"
                                "                            FROM users"
                                "                            WHERE users.uuid"
                                "                                  = '%s')))"
                                "       OR (subject_type = 'role'"
                                "           AND subject"
                                "               IN (SELECT DISTINCT role"
                                "                   FROM role_users"
                                "                   WHERE \"user\""
                                "                         = (SELECT id"
                                "                            FROM users"
                                "                            WHERE users.uuid"
                                "                                  = '%s'))))"
                                "  AND (%s))",
                                clause,
                                get->trash ? "_trash" : "",
                                current_credentials.uuid,
                                current_credentials.uuid,
                                current_credentials.uuid,
                                permission_or->str);
          else if (strcmp (type, "result") == 0)
            permission_clause
             = g_strdup_printf ("%s"
                                " OR EXISTS"
                                " (SELECT id FROM permissions"
                                "  WHERE resource = results%s.task"
                                "  AND resource_type = 'task'"
                                "  AND ((subject_type = 'user'"
                                "        AND subject"
                                "            = (SELECT id FROM users"
                                "               WHERE users.uuid = '%s'))"
                                "       OR (subject_type = 'group'"
                                "           AND subject"
                                "               IN (SELECT DISTINCT \"group\""
                                "                   FROM group_users"
                                "                   WHERE \"user\""
                                "                         = (SELECT id"
                                "                            FROM users"
                                "                            WHERE users.uuid"
                                "                                  = '%s')))"
                                "       OR (subject_type = 'role'"
                                "           AND subject"
                                "               IN (SELECT DISTINCT role"
                                "                   FROM role_users"
                                "                   WHERE \"user\""
                                "                         = (SELECT id"
                                "                            FROM users"
                                "                            WHERE users.uuid"
                                "                                  = '%s'))))"
                                "  AND (%s))",
                                clause,
                                get->trash ? "_trash" : "",
                                current_credentials.uuid,
                                current_credentials.uuid,
                                current_credentials.uuid,
                                permission_or->str);
          else
            permission_clause = clause;
        }
      else
        permission_clause = NULL;

      g_string_free (permission_or, TRUE);

      // FIX super trash?
      if (resource || (current_credentials.uuid == NULL))
        owned_clause
         = g_strdup (" (t ())");
      else if (get->trash && (strcasecmp (type, "task") == 0))
        owned_clause
         = g_strdup_printf (" (%ss.hidden = 2"
                            "  AND ((%ss.owner IS NULL)"
                            "       OR (%ss.owner"
                            "           = (SELECT id FROM users"
                            "              WHERE users.uuid = '%s'))"
                            "       %s))",
                            type,
                            type,
                            type,
                            current_credentials.uuid,
                            permission_clause ? permission_clause : "");
      else if (get->trash && type_is_shared (type))
        owned_clause
         = g_strdup_printf (" (((%ss_trash.owner IS NULL)"
                            "   AND user_can_everything ('%s'))"
                            "  %s)",
                            type,
                            current_credentials.uuid,
                            permission_clause ? permission_clause : "");
      else if (get->trash && type_has_permissions (type))
        owned_clause
         = g_strdup_printf (" ((%ss_trash.owner IS NULL)"
                            "  OR (%ss_trash.owner"
                            "      = (SELECT id FROM users"
                            "         WHERE users.uuid = '%s'))"
                            "  %s)",
                            type,
                            type,
                            current_credentials.uuid,
                            permission_clause ? permission_clause : "");
      else if (get->trash)
        owned_clause = g_strdup_printf (" ((owner IS NULL) OR (owner ="
                                        "  (SELECT id FROM users"
                                        "   WHERE users.uuid = '%s')))",
                                        current_credentials.uuid);
      else if (strcmp (type, "permission") == 0)
        {
          // FIX super
          int admin;
          admin = user_can_everything (current_credentials.uuid);
          /* A user sees permissions that involve the user.  Admin users also
           * see all higher level permissions. */
          owned_clause
           = g_strdup_printf (" ((%ss.owner = (SELECT id FROM users"
                              "                WHERE users.uuid = '%s'))"
                              "  %s"
                              "  OR (%ss.subject_type = 'user'"
                              "      AND %ss.subject"
                              "          = (SELECT id FROM users"
                              "             WHERE users.uuid = '%s'))"
                              "  OR (%ss.subject_type = 'group'"
                              "      AND %ss.subject"
                              "          IN (SELECT DISTINCT \"group\""
                              "              FROM group_users"
                              "              WHERE \"user\" = (SELECT id"
                              "                                FROM users"
                              "                                WHERE users.uuid"
                              "                                      = '%s')))"
                              "  OR (%ss.subject_type = 'role'"
                              "      AND %ss.subject"
                              "          IN (SELECT DISTINCT role"
                              "              FROM role_users"
                              "              WHERE \"user\" = (SELECT id"
                              "                                FROM users"
                              "                                WHERE users.uuid"
                              "                                      = '%s')))"
                              "  %s)",
                              type,
                              current_credentials.uuid,
                              admin ? "OR (permissions.owner IS NULL)" : "",
                              type,
                              type,
                              current_credentials.uuid,
                              type,
                              type,
                              current_credentials.uuid,
                              type,
                              type,
                              current_credentials.uuid,
                              permission_clause ? permission_clause : "");
        }
      else if (type_is_shared (type))
        // FIX super?
        owned_clause
         = g_strdup_printf (" (((%ss.owner IS NULL)"
                            "   AND user_can_everything ('%s'))"
                            "  %s)",
                            type,
                            current_credentials.uuid,
                            permission_clause ? permission_clause : "");
      else if (type_has_permissions (type))
        owned_clause
         = g_strdup_printf (/* Either a global resource. */
                            " ((%ss.owner IS NULL)"
                            /* Or the user is the owner. */
                            "  OR (%ss.owner"
                            "      = (SELECT id FROM users"
                            "         WHERE users.uuid = '%s'))"
                            /* Or the user has super permission. */
                            "  OR EXISTS (SELECT * FROM permissions"
                            "             WHERE name = 'Super'"
                            /*                 Super on everyone. */
                            "             AND ((resource = 0)"
                            /*                 Super on other_user. */
                            "                  OR ((resource_type = 'user')"
                            "                      AND (resource = %ss.owner))"
                            /*                 Super on other_user's role. */
                            "                  OR ((resource_type = 'role')"
                            "                      AND (resource"
                            "                           IN (SELECT DISTINCT role"
                            "                               FROM role_users"
                            "                               WHERE \"user\""
                            "                                     = %ss.owner)))"
                            /*                 Super on other_user's group. */
                            "                  OR ((resource_type = 'group')"
                            "                      AND (resource"
                            "                           IN (SELECT DISTINCT \"group\""
                            "                               FROM group_users"
                            "                               WHERE \"user\""
                            "                                     = %ss.owner))))"
                            "             AND ((subject_type = 'user'"
                            "                   AND subject"
                            "                       = (SELECT id FROM users"
                            "                          WHERE users.uuid = '%s'))"
                            "                  OR (subject_type = 'group'"
                            "                      AND subject"
                            "                          IN (SELECT DISTINCT \"group\""
                            "                              FROM group_users"
                            "                              WHERE \"user\""
                            "                                    = (SELECT id"
                            "                                       FROM users"
                            "                                       WHERE users.uuid"
                            "                                             = '%s')))"
                            "                  OR (subject_type = 'role'"
                            "                      AND subject"
                            "                          IN (SELECT DISTINCT role"
                            "                              FROM role_users"
                            "                              WHERE \"user\""
                            "                                    = (SELECT id"
                            "                                       FROM users"
                            "                                       WHERE users.uuid"
                            "                                             = '%s')))))"
                            "  %s)",
                            type,
                            type,
                            current_credentials.uuid,
                            type,
                            type,
                            type,
                            current_credentials.uuid,
                            current_credentials.uuid,
                            current_credentials.uuid,
                            permission_clause ? permission_clause : "");
      else
        // FIX super
        owned_clause = g_strdup_printf (" ((%ss.owner IS NULL) OR (%ss.owner ="
                                        "  (SELECT id FROM users"
                                        "   WHERE users.uuid = '%s')))",
                                        type,
                                        type,
                                        current_credentials.uuid);

      if (owner_filter && (strcmp (owner_filter, "any") == 0))
        filter_owned_clause = g_strdup (owned_clause);
      else if (owner_filter)
        {
          gchar *quoted;
          quoted = sql_quote (owner_filter);
          filter_owned_clause = g_strdup_printf ("(owner = (SELECT id FROM users"
                                                 "          WHERE name = '%s')"
                                                 " AND %s)",
                                                 quoted,
                                                 owned_clause);
          g_free (quoted);
        }
      else
        filter_owned_clause = g_strdup_printf ("((owner = (SELECT id FROM users"
                                               "           WHERE uuid = '%s')"
                                               "  OR owner IS NULL)"
                                               " AND %s)",
                                               current_credentials.uuid,
                                               owned_clause);

      g_free (owned_clause);
      owned_clause = filter_owned_clause;
    }
  else
   owned_clause = g_strdup (" t ()");

  return owned_clause;
}
