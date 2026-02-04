/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_resources.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "manage_sql_permissions.h"
#include "manage_sql_tls_certificates.h"
#include "manage_sql_users.h"
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

/* TODO Only used by find_permission and check_permission_args. */
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

/**
 * @brief Create a resource from an existing resource.
 *
 * @param[in]  type          Type of resource.
 * @param[in]  name          Name of new resource.  NULL to copy from existing.
 * @param[in]  comment       Comment on new resource.  NULL to copy from existing.
 * @param[in]  resource_id   UUID of existing resource.
 * @param[in]  columns       Extra columns in resource.
 * @param[in]  make_name_unique  When name NULL, whether to make existing name
 *                               unique.
 * @param[out] new_resource  Address for new resource, or NULL.
 * @param[out] old_resource  Address for existing resource, or NULL.
 *
 * @return 0 success, 1 resource exists already, 2 failed to find existing
 *         resource, 99 permission denied, -1 error.
 */
int
copy_resource_lock (const char *type, const char *name, const char *comment,
                    const char *resource_id, const char *columns,
                    int make_name_unique, resource_t* new_resource,
                    resource_t *old_resource)
{
  gchar *quoted_name, *quoted_uuid, *uniquify, *command;
  int named, globally_unique;
  user_t owner;
  resource_t resource;
  resource_t new;
  int ret = -1;

  if (resource_id == NULL)
    return -1;

  command = g_strdup_printf ("create_%s", type);
  if (acl_user_may (command) == 0)
    {
      g_free (command);
      return 99;
    }
  g_free (command);

  command = g_strdup_printf ("get_%ss", type);
  if (find_resource_with_permission (type, resource_id, &resource, command, 0))
    {
      g_free (command);
      return -1;
    }
  g_free (command);

  if (resource == 0)
    return 2;

  if (find_user_by_name (current_credentials.username, &owner)
      || owner == 0)
    {
      return -1;
    }

  if (strcmp (type, "permission") == 0)
    {
      resource_t perm_resource;
      perm_resource = permission_resource (resource);
      if ((perm_resource == 0)
          && (acl_user_can_everything (current_credentials.uuid) == 0))
        /* Only admins can copy permissions that apply to whole commands. */
        return 99;
    }

  named = type_named (type);
  globally_unique = type_globally_unique (type);

  if (named && name && *name && resource_with_name_exists (name, type, 0))
    return 1;

  if ((strcmp (type, "tls_certificate") == 0)
      && user_has_tls_certificate (resource, owner))
    return 1;

  if (name && *name)
    quoted_name = sql_quote (name);
  else
    quoted_name = NULL;
  quoted_uuid = sql_quote (resource_id);

  /* Copy the existing resource. */

  if (globally_unique && make_name_unique)
    uniquify = g_strdup_printf ("uniquify ('%s', name, NULL, '%cClone')",
                                type,
                                strcmp (type, "user") ? ' ' : '_');
  else if (make_name_unique)
    uniquify = g_strdup_printf ("uniquify ('%s', name, %llu, ' Clone')",
                                type,
                                owner);
  else
    uniquify = g_strdup ("name");
  if (named && comment && strlen (comment))
    {
      gchar *quoted_comment;
      quoted_comment = sql_nquote (comment, strlen (comment));
      ret = sql_error ("INSERT INTO %ss"
                       " (uuid, owner, name, comment,"
                       "  creation_time, modification_time%s%s)"
                       " SELECT make_uuid (),"
                       "        (SELECT id FROM users"
                       "         where users.uuid = '%s'),"
                       "        %s%s%s, '%s', m_now (), m_now ()%s%s"
                       " FROM %ss WHERE uuid = '%s';",
                       type,
                       columns ? ", " : "",
                       columns ? columns : "",
                       current_credentials.uuid,
                       quoted_name ? "'" : "",
                       quoted_name ? quoted_name : uniquify,
                       quoted_name ? "'" : "",
                       quoted_comment,
                       columns ? ", " : "",
                       columns ? columns : "",
                       type,
                       quoted_uuid);
      g_free (quoted_comment);
    }
  else if (named)
    ret = sql_error ("INSERT INTO %ss"
                      " (uuid, owner, name%s,"
                      "  creation_time, modification_time%s%s)"
                      " SELECT make_uuid (),"
                      "        (SELECT id FROM users where users.uuid = '%s'),"
                      "        %s%s%s%s, m_now (), m_now ()%s%s"
                      " FROM %ss WHERE uuid = '%s';",
                      type,
                      type_has_comment (type) ? ", comment" : "",
                      columns ? ", " : "",
                      columns ? columns : "",
                      current_credentials.uuid,
                      quoted_name ? "'" : "",
                      quoted_name ? quoted_name : uniquify,
                      quoted_name ? "'" : "",
                      type_has_comment (type) ? ", comment" : "",
                      columns ? ", " : "",
                      columns ? columns : "",
                      type,
                      quoted_uuid);
  else
    ret = sql_error ("INSERT INTO %ss"
                     " (uuid, owner, creation_time, modification_time%s%s)"
                     " SELECT make_uuid (),"
                     "        (SELECT id FROM users where users.uuid = '%s'),"
                     "        m_now (), m_now ()%s%s"
                     " FROM %ss WHERE uuid = '%s';",
                     type,
                     columns ? ", " : "",
                     columns ? columns : "",
                     current_credentials.uuid,
                     columns ? ", " : "",
                     columns ? columns : "",
                     type,
                     quoted_uuid);

  if (ret == 3)
    {
      g_free (quoted_uuid);
      g_free (quoted_name);
      g_free (uniquify);
      return 1;
    }
  else if (ret)
    {
      g_free (quoted_uuid);
      g_free (quoted_name);
      g_free (uniquify);
      return -1;
    }

  new = sql_last_insert_id ();

  /* Copy attached tags */
  sql ("INSERT INTO tag_resources"
       " (tag, resource_type, resource, resource_uuid, resource_location)"
       " SELECT tag, resource_type, %llu,"
       "        (SELECT uuid FROM %ss WHERE id = %llu),"
       "        resource_location"
       "   FROM tag_resources"
       "  WHERE resource_type = '%s' AND resource = %llu"
       "    AND resource_location = " G_STRINGIFY (LOCATION_TABLE) ";",
       new,
       type, new,
       type, resource);

  if (new_resource)
    *new_resource = new;

  if (old_resource)
    *old_resource = resource;

  g_free (quoted_uuid);
  g_free (quoted_name);
  g_free (uniquify);
  if (sql_last_insert_id () == 0)
    return -1;
  return 0;
}

/**
 * @brief Create a resource from an existing resource.
 *
 * @param[in]  type          Type of resource.
 * @param[in]  name          Name of new resource.  NULL to copy from existing.
 * @param[in]  comment       Comment on new resource.  NULL to copy from existing.
 * @param[in]  resource_id   UUID of existing resource.
 * @param[in]  columns       Extra columns in resource.
 * @param[in]  make_name_unique  When name NULL, whether to make existing name
 *                               unique.
 * @param[out] new_resource  New resource.
 * @param[out] old_resource  Address for existing resource, or NULL.
 *
 * @return 0 success, 1 resource exists already, 2 failed to find existing
 *         resource, 99 permission denied, -1 error.
 */
int
copy_resource (const char *type, const char *name, const char *comment,
               const char *resource_id, const char *columns,
               int make_name_unique, resource_t* new_resource,
               resource_t *old_resource)
{
  int ret;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  ret = copy_resource_lock (type, name, comment, resource_id, columns,
                            make_name_unique, new_resource, old_resource);

  if (ret)
    sql_rollback ();
  else
    sql_commit ();

  return ret;
}

/**
 * @brief Check if a resource has been marked as deprecated.
 *
 * @param[in]  type         Resource type.
 * @param[in]  resource_id  UUID of the resource.
 *
 * @return 1 if deprecated, else 0.
 */
int
resource_id_deprecated (const char *type, const char *resource_id)
{
  int ret;
  gchar *quoted_type = sql_quote (type);
  gchar *quoted_uuid = sql_quote (resource_id);

  ret = sql_int ("SELECT count(*) FROM deprecated_feed_data"
                 " WHERE type = '%s' AND uuid = '%s';",
                 quoted_type, quoted_uuid);

  g_free (quoted_type);
  g_free (quoted_uuid);

  return ret != 0;
}

/**
 * @brief Mark whether resource is deprecated.
 *
 * @param[in]  type         Resource type.
 * @param[in]  resource_id  UUID of the resource.
 * @param[in]  deprecated   Whether the resource is deprecated.
 */
void
set_resource_id_deprecated (const char *type, const char *resource_id,
                            gboolean deprecated)
{
  gchar *quoted_type = sql_quote (type);
  gchar *quoted_uuid = sql_quote (resource_id);

  if (deprecated)
    {
      sql ("INSERT INTO deprecated_feed_data (type, uuid, modification_time)"
           " VALUES ('%s', '%s', m_now ())"
           " ON CONFLICT (uuid, type)"
           " DO UPDATE SET modification_time = m_now ()",
           quoted_type, quoted_uuid);
    }
  else
    {
      sql ("DELETE FROM deprecated_feed_data"
           " WHERE type = '%s' AND uuid = '%s'",
           quoted_type, quoted_uuid);
    }
  g_free (quoted_type);
  g_free (quoted_uuid);
}

/**
 * @brief Return number of resources of a certain type for current user.
 *
 * @param[in]  type  Type.
 * @param[in]  get   GET params.
 *
 * @return The number of resources associated with the current user.
 */
int
resource_count (const char *type, const get_data_t *get)
{
  static const char *filter_columns[] = { "owner", NULL };
  static column_t select_columns[] = {{ "owner", NULL }, { NULL, NULL }};
  get_data_t count_get;
  gchar *extra_where, *extra_with, *extra_tables;
  int rc;

  memset (&count_get, '\0', sizeof (count_get));
  count_get.trash = get->trash;
  if (type_owned (type))
    count_get.filter = "rows=-1 first=1 permission=any owner=any min_qod=0";
  else
    count_get.filter = "rows=-1 first=1 permission=any min_qod=0";

  extra_with = extra_tables = NULL;

  if (strcasecmp (type, "config") == 0)
    {
      const gchar *usage_type = get_data_get_extra (get, "usage_type");
      extra_where = configs_extra_where (usage_type);
    }
  else if (strcmp (type, "task") == 0)
    {
      const gchar *usage_type = get_data_get_extra (get, "usage_type");
      extra_where = tasks_extra_where (get->trash, usage_type);
    }
  else if (strcmp (type, "report") == 0)
    {
      const gchar *usage_type = get_data_get_extra (get, "usage_type");
      extra_where = reports_extra_where (0, NULL, usage_type);
    }
  else if (strcmp (type, "result") == 0)
    {
      extra_where
        = g_strdup (" AND (severity != " G_STRINGIFY (SEVERITY_ERROR) ")");
    }
  else if (strcmp (type, "vuln") == 0)
    {
      extra_where = vulns_extra_where (filter_term_min_qod (count_get.filter));
      extra_with = vuln_iterator_extra_with_from_filter (count_get.filter);
      extra_tables = vuln_iterator_opts_from_filter (count_get.filter);
    }
  else
    extra_where = NULL;

  rc = count2 (get->subtype ? get->subtype : type,
               &count_get,
               type_owned (type) ? select_columns : NULL,
               type_owned (type) ? select_columns : NULL,
               NULL,
               NULL,
               type_owned (type) ? filter_columns : NULL,
               0,
               extra_tables,
               extra_where,
               extra_with,
               type_owned (type));

  g_free (extra_where);
  g_free (extra_with);
  g_free (extra_tables);
  return rc;
}
