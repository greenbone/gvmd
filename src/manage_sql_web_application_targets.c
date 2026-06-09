/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Web Application Targets SQL.
 *
 * SQL web application targets code for the GVM management layer.
 */

#if ENABLE_WEB_APPLICATION_SCANNING

#include "debug_utils.h"
#include "manage_sql_web_application_targets.h"
#include "manage_acl.h"
#include "manage_sql_permissions.h"
#include "manage_sql_resources.h"
#include "manage_sql_tags.h"
#include "sql.h"
#include "utils.h"

#include <glib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Create a web application target.
 *
 * @param[in]   data                    Web application target data.
 * @param[out]  web_application_target  Created target.
 * @param[out]  error_message           Error message if any.
 *
 * @return A member of create_web_application_target_return_t.
 */
create_web_application_target_resp_t
create_web_application_target (web_application_target_data_t data,
                               web_application_target_t *web_application_target,
                               gchar **error_message)
{
  web_application_target_t new_web_application_target;
  credential_t credential = 0;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  if (acl_user_may ("create_web_application_target") == 0)
    {
      sql_rollback ();
      return CREATE_WEB_APPLICATION_TARGET_PERMISSION_DENIED;
    }

  if (resource_with_name_exists (data->name, "web_application_target", 0))
    {
      sql_rollback ();
      return CREATE_WEB_APPLICATION_TARGET_EXISTS_ALREADY;
    }

  gchar *clean_target_urls = clean_urls (data->urls);
  if (!clean_target_urls
      || !validate_web_application_urls (clean_target_urls, error_message))
    {
      sql_rollback ();
      g_free (clean_target_urls);
      return CREATE_WEB_APPLICATION_TARGET_INVALID_URLS;
    }

  gchar *clean_exclude_urls = NULL;
  if (data->exclude_urls && strlen (data->exclude_urls) > 0)
    {
      clean_exclude_urls = clean_urls (data->exclude_urls);
      if (!clean_exclude_urls
          || !validate_web_application_urls (clean_exclude_urls,
                                             error_message))
        {
          sql_rollback ();
          g_free (clean_target_urls);
          g_free (clean_exclude_urls);
          return CREATE_WEB_APPLICATION_TARGET_INVALID_EXCLUDE_URLS;
        }
    }

  if (data->credential_uuid)
    {
      if (strcmp (data->credential_uuid, "0"))
        {
          gchar *type;

          if (find_credential_with_permission (data->credential_uuid,
                                               &credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              g_free (clean_target_urls);
              g_free (clean_exclude_urls);
              return CREATE_WEB_APPLICATION_TARGET_INTERNAL_ERROR;
            }

          if (credential == 0)
            {
              sql_rollback ();
              g_free (clean_target_urls);
              g_free (clean_exclude_urls);
              return CREATE_WEB_APPLICATION_TARGET_CREDENTIAL_NOT_FOUND;
            }

          type = credential_type (credential);

          /* For now this follows the OCI implementation and accepts
           * username/password credentials only.
           */
          if (strcmp (type, "up"))
            {
              sql_rollback ();
              g_free (type);
              g_free (clean_target_urls);
              g_free (clean_exclude_urls);
              return CREATE_WEB_APPLICATION_TARGET_INVALID_CREDENTIAL_TYPE;
            }

          g_free (type);
        }
      else
        {
          sql_rollback ();
          g_free (clean_target_urls);
          g_free (clean_exclude_urls);
          return CREATE_WEB_APPLICATION_TARGET_INVALID_CREDENTIAL;
        }
    }

  sql_ps ("INSERT INTO web_application_targets"
          " (uuid, name, owner, urls, exclude_urls,"
          "  comment, creation_time, modification_time)"
          " VALUES (make_uuid (), $1,"
          " (SELECT id FROM users WHERE users.uuid = $2),"
          " $3, $4, $5, m_now (), m_now ());",
          SQL_STR_PARAM (data->name),
          SQL_STR_PARAM (current_credentials.uuid),
          SQL_STR_PARAM (clean_target_urls),
          clean_exclude_urls
            ? SQL_STR_PARAM (clean_exclude_urls)
            : SQL_NULL_PARAM,
          data->comment ? SQL_STR_PARAM (data->comment) : SQL_NULL_PARAM,
          NULL);

  new_web_application_target = sql_last_insert_id ();

  if (credential)
    sql_ps ("UPDATE web_application_targets SET credential = $1"
            " WHERE id = $2;",
            SQL_RESOURCE_PARAM (credential),
            SQL_RESOURCE_PARAM (new_web_application_target),
            NULL);

  if (web_application_target)
    *web_application_target = new_web_application_target;

  sql_commit ();

  g_free (clean_target_urls);
  g_free (clean_exclude_urls);

  return CREATE_WEB_APPLICATION_TARGET_OK;
}

/**
 * @brief Create a web application target from an existing one.
 *
 * @param[in]  name                         Name of new target.
 * @param[in]  comment                      Comment on new target.
 * @param[in]  web_application_target_id    UUID of existing target.
 * @param[out] new_web_application_target   New target.
 *
 * @return 0 success, 1 target exists already, 2 failed to find existing
 *         target, 99 permission denied, -1 error.
 */
int
copy_web_application_target (const char *name,
                             const char *comment,
                             const char *web_application_target_id,
                             web_application_target_t *
                             new_web_application_target)
{
  int ret;
  web_application_target_t old_web_application_target;

  assert (new_web_application_target);

  ret = copy_resource ("web_application_target",
                       name,
                       comment,
                       web_application_target_id,
                       "credential, urls, exclude_urls",
                       1,
                       new_web_application_target,
                       &old_web_application_target);

  if (ret)
    return ret;

  return 0;
}

/**
 * @brief Modify a web application target.
 *
 * @param[in]   data             Web application target data to modify.
 * @param[out]  error_message    Error message if any.
 *
 * @return A member of modify_web_application_target_return_t.
 */
modify_web_application_target_resp_t
modify_web_application_target (web_application_target_data_t data,
                               gchar **error_message)
{
  web_application_target_t web_application_target;
  credential_t credential;

  assert (data->uuid);
  assert (current_credentials.uuid);

  sql_begin_immediate ();

  if (acl_user_may ("modify_web_application_target") == 0)
    {
      sql_rollback ();
      return MODIFY_WEB_APPLICATION_TARGET_PERMISSION_DENIED;
    }

  web_application_target = 0;
  if (find_web_application_target_with_permission (data->uuid,
                                                   &web_application_target,
                                                   "modify_web_application_target"))
    {
      sql_rollback ();
      return MODIFY_WEB_APPLICATION_TARGET_INTERNAL_ERROR;
    }

  if (web_application_target == 0)
    {
      sql_rollback ();
      return MODIFY_WEB_APPLICATION_TARGET_NOT_FOUND;
    }

  if (data->name)
    {
      if (strlen (data->name) == 0)
        {
          sql_rollback ();
          return MODIFY_WEB_APPLICATION_TARGET_INVALID_NAME;
        }

      if (resource_with_name_exists (data->name,
                                     "web_application_target",
                                     web_application_target))
        {
          sql_rollback ();
          return MODIFY_WEB_APPLICATION_TARGET_EXISTS_ALREADY;
        }

      sql_ps ("UPDATE web_application_targets SET"
              " name = $1,"
              " modification_time = m_now ()"
              " WHERE id = $2;",
              SQL_STR_PARAM (data->name),
              SQL_RESOURCE_PARAM (web_application_target),
              NULL);
    }

  if (data->comment)
    {
      sql_ps ("UPDATE web_application_targets SET"
              " comment = $1,"
              " modification_time = m_now ()"
              " WHERE id = $2;",
              SQL_STR_PARAM (data->comment),
              SQL_RESOURCE_PARAM (web_application_target),
              NULL);
    }

  if (data->credential_uuid)
    {
      if (web_application_target_in_use (web_application_target))
        {
          sql_rollback ();
          return MODIFY_WEB_APPLICATION_TARGET_IN_USE;
        }

      credential = 0;

      if (strcmp (data->credential_uuid, "0"))
        {
          gchar *type;

          if (find_credential_with_permission (data->credential_uuid,
                                               &credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              return MODIFY_WEB_APPLICATION_TARGET_INTERNAL_ERROR;
            }

          if (credential == 0)
            {
              sql_rollback ();
              return MODIFY_WEB_APPLICATION_TARGET_CREDENTIAL_NOT_FOUND;
            }

          type = credential_type (credential);

          if (strcmp (type, "up"))
            {
              sql_rollback ();
              g_free (type);
              return MODIFY_WEB_APPLICATION_TARGET_INVALID_CREDENTIAL_TYPE;
            }

          g_free (type);

          sql_ps ("UPDATE web_application_targets SET"
                  " credential = $1,"
                  " modification_time = m_now ()"
                  " WHERE id = $2;",
                  SQL_RESOURCE_PARAM (credential),
                  SQL_RESOURCE_PARAM (web_application_target),
                  NULL);
        }
      else
        {
          sql_ps ("UPDATE web_application_targets SET"
                  " credential = NULL,"
                  " modification_time = m_now ()"
                  " WHERE id = $1;",
                  SQL_RESOURCE_PARAM (web_application_target),
                  NULL);
        }
    }

  if (data->urls)
    {
      gchar *clean_target_urls = clean_urls (data->urls);

      if (!clean_target_urls
          || !validate_web_application_urls (clean_target_urls,
                                             error_message))
        {
          sql_rollback ();
          g_free (clean_target_urls);
          return MODIFY_WEB_APPLICATION_TARGET_INVALID_URLS;
        }

      sql_ps ("UPDATE web_application_targets SET"
              " urls = $1,"
              " modification_time = m_now ()"
              " WHERE id = $2;",
              SQL_STR_PARAM (clean_target_urls),
              SQL_RESOURCE_PARAM (web_application_target),
              NULL);

      g_free (clean_target_urls);
    }

  if (data->exclude_urls)
    {
      if (g_str_equal (data->exclude_urls, ""))
        {
          sql_ps ("UPDATE web_application_targets SET"
                  " exclude_urls = NULL,"
                  " modification_time = m_now ()"
                  " WHERE id = $1;",
                  SQL_RESOURCE_PARAM (web_application_target),
                  NULL);
        }
      else
        {
          gchar *clean_exclude_urls = clean_urls (data->exclude_urls);

          if (!clean_exclude_urls
              || !validate_web_application_urls (clean_exclude_urls,
                                                 error_message))
            {
              sql_rollback ();
              g_free (clean_exclude_urls);
              return MODIFY_WEB_APPLICATION_TARGET_INVALID_EXCLUDE_URLS;
            }

          sql_ps ("UPDATE web_application_targets SET"
                  " exclude_urls = $1,"
                  " modification_time = m_now ()"
                  " WHERE id = $2;",
                  SQL_STR_PARAM (clean_exclude_urls),
                  SQL_RESOURCE_PARAM (web_application_target),
                  NULL);

          g_free (clean_exclude_urls);
        }
    }

  sql_commit ();

  return MODIFY_WEB_APPLICATION_TARGET_OK;
}

/**
 * @brief Delete a web application target.
 *
 * @param[in]  web_application_target_id  UUID of target.
 * @param[in]  ultimate                   Whether to remove entirely,
 *                                        or move to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the target, 2 failed
 *         to find target, 99 permission denied, -1 error.
 */
int
delete_web_application_target (
  const char *web_application_target_id, int ultimate)
{
  web_application_target_t web_application_target = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_web_application_target") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_web_application_target_with_permission (web_application_target_id,
                                                   &web_application_target,
                                                   "delete_web_application_target"))
    {
      sql_rollback ();
      return -1;
    }

  if (web_application_target == 0)
    {
      if (find_trash ("web_application_target",
                      web_application_target_id,
                      &web_application_target))
        {
          sql_rollback ();
          return -1;
        }

      if (web_application_target == 0)
        {
          sql_rollback ();
          return 2;
        }

      if (ultimate == 0)
        {
          sql_commit ();
          return 0;
        }

      if (sql_int_ps ("SELECT count(*) FROM tasks"
                      " WHERE web_application_target = $1"
                      " AND web_application_target_location = "
                      G_STRINGIFY (LOCATION_TRASH) ";",
                      SQL_RESOURCE_PARAM (web_application_target),
                      NULL))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("web_application_target",
                               web_application_target,
                               LOCATION_TRASH);

      tags_remove_resource ("web_application_target",
                            web_application_target,
                            LOCATION_TRASH);

      sql_ps ("DELETE FROM web_application_targets_trash"
              " WHERE id = $1;",
              SQL_RESOURCE_PARAM (web_application_target),
              NULL);

      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      web_application_target_t trash_web_application_target;

      if (sql_int_ps ("SELECT count(*) FROM tasks"
                      " WHERE web_application_target = $1"
                      " AND web_application_target_location = "
                      G_STRINGIFY (LOCATION_TABLE)
                      " AND hidden = 0;",
                      SQL_RESOURCE_PARAM (web_application_target),
                      NULL))
        {
          sql_rollback ();
          return 1;
        }

      sql_ps ("INSERT INTO web_application_targets_trash"
              " (uuid, owner, name, urls, exclude_urls,"
              "  comment, credential, credential_location,"
              "  creation_time, modification_time)"
              " SELECT uuid, owner, name, urls, exclude_urls,"
              " comment, credential, " G_STRINGIFY (LOCATION_TABLE) ","
              " creation_time, modification_time"
              " FROM web_application_targets WHERE id = $1;",
              SQL_RESOURCE_PARAM (web_application_target),
              NULL);

      trash_web_application_target = sql_last_insert_id ();

      sql_ps ("UPDATE tasks"
              " SET web_application_target = $1,"
              "     web_application_target_location = "
              G_STRINGIFY (LOCATION_TRASH)
              " WHERE web_application_target = $2"
              " AND web_application_target_location = "
              G_STRINGIFY (LOCATION_TABLE) ";",
              SQL_RESOURCE_PARAM (trash_web_application_target),
              SQL_RESOURCE_PARAM (web_application_target),
              NULL);

      permissions_set_locations ("web_application_target",
                                 web_application_target,
                                 trash_web_application_target,
                                 LOCATION_TRASH);

      tags_set_locations ("web_application_target",
                          web_application_target,
                          trash_web_application_target,
                          LOCATION_TRASH);
    }
  else if (sql_int_ps ("SELECT count(*) FROM tasks"
                       " WHERE web_application_target = $1"
                       " AND web_application_target_location = "
                       G_STRINGIFY (LOCATION_TABLE) ";",
                       SQL_RESOURCE_PARAM (web_application_target),
                       NULL))
    {
      sql_rollback ();
      return 1;
    }
  else
    {
      permissions_set_orphans ("web_application_target",
                               web_application_target,
                               LOCATION_TABLE);

      tags_remove_resource ("web_application_target",
                            web_application_target,
                            LOCATION_TABLE);
    }

  sql_ps ("DELETE FROM web_application_targets WHERE id = $1;",
          SQL_RESOURCE_PARAM (web_application_target),
          NULL);

  sql_commit ();
  return 0;
}

/**
 * @brief Try restore a web application target.
 *
 * If success, ends transaction for caller before exiting.
 *
 * @param[in]  web_application_target_id  UUID of resource.
 *
 * @return 0 success, 1 fail because resource is in use, 2 failed to find
 *         resource, 3 fail because resource with same name exists,
 *         4 fail because resource with same UUID exists, -1 error.
 */
int
restore_web_application_target (const char *web_application_target_id)
{
  web_application_target_t resource, web_application_target;

  if (find_trash ("web_application_target",
                  web_application_target_id,
                  &resource))
    {
      sql_rollback ();
      return -1;
    }

  if (resource == 0)
    return 2;

  if (sql_int_ps ("SELECT credential_location = "
                  G_STRINGIFY (LOCATION_TRASH)
                  " FROM web_application_targets_trash WHERE id = $1;",
                  SQL_RESOURCE_PARAM (resource),
                  NULL))
    {
      sql_rollback ();
      return 1;
    }

  if (sql_int_ps ("SELECT count(*) FROM web_application_targets"
                  " WHERE name ="
                  " (SELECT name FROM web_application_targets_trash"
                  "  WHERE id = $1)"
                  " AND owner ="
                  " (SELECT users.id FROM users"
                  "  WHERE users.uuid = $2);",
                  SQL_RESOURCE_PARAM (resource),
                  SQL_STR_PARAM (current_credentials.uuid),
                  NULL))
    {
      sql_rollback ();
      return 3;
    }

  if (sql_int_ps ("SELECT count(*) FROM web_application_targets"
                  " WHERE uuid ="
                  " (SELECT uuid FROM web_application_targets_trash"
                  "  WHERE id = $1);",
                  SQL_RESOURCE_PARAM (resource),
                  NULL))
    {
      sql_rollback ();
      return 4;
    }

  sql_ps ("INSERT INTO web_application_targets"
          " (uuid, owner, name, comment, creation_time, modification_time,"
          "  urls, exclude_urls, credential)"
          " SELECT"
          "  uuid, owner, name, comment, creation_time, modification_time,"
          "  urls, exclude_urls, credential"
          " FROM web_application_targets_trash"
          " WHERE id = $1;",
          SQL_RESOURCE_PARAM (resource),
          NULL);

  web_application_target = sql_last_insert_id ();

  sql_ps ("UPDATE tasks"
          " SET web_application_target = $1,"
          " web_application_target_location = "
          G_STRINGIFY (LOCATION_TABLE)
          " WHERE web_application_target = $2"
          " AND web_application_target_location = "
          G_STRINGIFY (LOCATION_TRASH) ";",
          SQL_RESOURCE_PARAM (web_application_target),
          SQL_RESOURCE_PARAM (resource),
          NULL);

  permissions_set_locations ("web_application_target",
                             resource,
                             web_application_target,
                             LOCATION_TABLE);

  tags_set_locations ("web_application_target",
                      resource,
                      web_application_target,
                      LOCATION_TABLE);

  sql_ps ("DELETE FROM web_application_targets_trash WHERE id = $1;",
          SQL_RESOURCE_PARAM (resource),
          NULL);

  sql_commit ();
  return 0;
}

/**
 * @brief Count number of web application targets.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of web application targets in filtered set.
 */
int
web_application_target_count (const get_data_t *get)
{
  static const char *extra_columns[]
    = WEB_APPLICATION_TARGET_ITERATOR_FILTER_COLUMNS;
  static column_t columns[]
    = WEB_APPLICATION_TARGET_ITERATOR_COLUMNS;
  static column_t trash_columns[]
    = WEB_APPLICATION_TARGET_ITERATOR_TRASH_COLUMNS;

  return count ("web_application_target",
                get,
                columns,
                trash_columns,
                extra_columns,
                0,
                0,
                0,
                TRUE);
}

/**
 * @brief Initialise a web application target iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  get       GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_web_application_target_iterator (iterator_t *iterator, get_data_t *get)
{
  static const char *filter_columns[]
    = WEB_APPLICATION_TARGET_ITERATOR_FILTER_COLUMNS;
  static column_t columns[]
    = WEB_APPLICATION_TARGET_ITERATOR_COLUMNS;
  static column_t trash_columns[]
    = WEB_APPLICATION_TARGET_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "web_application_target",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}

/**
 * @brief Get the URLs from a web application target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return URLs of the target or NULL if iteration is complete.
 */
DEF_ACCESS (web_application_target_iterator_urls,
            GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the excluded URLs from a web application target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Excluded URLs of the target or NULL if iteration is complete.
 */
DEF_ACCESS (web_application_target_iterator_exclude_urls,
            GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the credential from a web application target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Credential of the target or 0 if the iteration is complete.
 */
credential_t
web_application_target_iterator_credential (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
}

/**
 * @brief Get the credential name from a web application target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Credential name, or NULL if iteration is complete.
 */
DEF_ACCESS (web_application_target_iterator_credential_name,
            GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the credential location from a web application target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Location of the credential or 0 if iteration is complete.
 */
int
web_application_target_iterator_credential_trash (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
}

/**
 * @brief Return the UUID of a web application target.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char *
web_application_target_uuid (web_application_target_t web_application_target)
{
  return sql_string_ps ("SELECT uuid FROM web_application_targets"
                        " WHERE id = $1;",
                        SQL_RESOURCE_PARAM (web_application_target),
                        NULL);
}

/**
 * @brief Return the UUID of a trashcan web application target.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char *
trash_web_application_target_uuid (
  web_application_target_t web_application_target)
{
  return sql_string_ps ("SELECT uuid FROM web_application_targets_trash"
                        " WHERE id = $1;",
                        SQL_RESOURCE_PARAM (web_application_target),
                        NULL);
}

/**
 * @brief Return the name of a web application target.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char *
web_application_target_name (web_application_target_t web_application_target)
{
  return sql_string_ps ("SELECT name FROM web_application_targets"
                        " WHERE id = $1;",
                        SQL_RESOURCE_PARAM (web_application_target),
                        NULL);
}

/**
 * @brief Return the name of a trashcan web application target.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char *
trash_web_application_target_name (
  web_application_target_t web_application_target)
{
  return sql_string_ps ("SELECT name FROM web_application_targets_trash"
                        " WHERE id = $1;",
                        SQL_RESOURCE_PARAM (web_application_target),
                        NULL);
}

/**
 * @brief Return the comment of a web application target.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return Newly allocated comment if available, else NULL.
 */
char *
web_application_target_comment (web_application_target_t web_application_target)
{
  return sql_string_ps ("SELECT comment FROM web_application_targets"
                        " WHERE id = $1;",
                        SQL_RESOURCE_PARAM (web_application_target),
                        NULL);
}

/**
 * @brief Return the comment of a trashcan web application target.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return Newly allocated comment if available, else NULL.
 */
char *
trash_web_application_target_comment (
  web_application_target_t web_application_target)
{
  return sql_string_ps ("SELECT comment FROM web_application_targets_trash"
                        " WHERE id = $1;",
                        SQL_RESOURCE_PARAM (web_application_target),
                        NULL);
}

/**
 * @brief Return the URLs of a web application target.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return Newly allocated comma-separated list of URLs if available,
 *         else NULL.
 */
char *
web_application_target_urls (web_application_target_t web_application_target)
{
  return sql_string_ps ("SELECT urls FROM web_application_targets"
                        " WHERE id = $1;",
                        SQL_RESOURCE_PARAM (web_application_target),
                        NULL);
}

/**
 * @brief Return the excluded URLs of a web application target.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return Newly allocated comma-separated list of excluded URLs if available,
 *         else NULL.
 */
char *
web_application_target_exclude_urls (
  web_application_target_t web_application_target)
{
  return sql_string_ps ("SELECT exclude_urls FROM web_application_targets"
                        " WHERE id = $1;",
                        SQL_RESOURCE_PARAM (web_application_target),
                        NULL);
}

/**
 * @brief Return whether a trashcan web application target is readable.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return 1 if readable, else 0.
 */
int
trash_web_application_target_readable (
  web_application_target_t web_application_target)
{
  char *uuid;
  web_application_target_t found = 0;

  if (web_application_target == 0)
    return 0;

  uuid = web_application_target_uuid (web_application_target);

  if (find_trash ("web_application_target", uuid, &found))
    {
      g_free (uuid);
      return 0;
    }

  g_free (uuid);
  return found > 0;
}

/**
 * @brief Return whether a web application target is in use by a task.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return 1 if in use, else 0.
 */
int
web_application_target_in_use (web_application_target_t web_application_target)
{
  return !!sql_int_ps ("SELECT count(*) FROM tasks"
                       " WHERE web_application_target = $1"
                       " AND web_application_target_location = "
                       G_STRINGIFY (LOCATION_TABLE)
                       " AND hidden = 0;",
                       SQL_RESOURCE_PARAM (web_application_target),
                       NULL);
}

/**
 * @brief Return whether a trashcan web application target is referenced
 *        by a task.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return 1 if in use, else 0.
 */
int
trash_web_application_target_in_use (
  web_application_target_t web_application_target)
{
  return !!sql_int_ps ("SELECT count(*) FROM tasks"
                       " WHERE web_application_target = $1"
                       " AND web_application_target_location = "
                       G_STRINGIFY (LOCATION_TRASH) ";",
                       SQL_RESOURCE_PARAM (web_application_target),
                       NULL);
}

/**
 * @brief Get a credential from a web application target.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return The credential, or 0 if none or error.
 */
credential_t
web_application_target_credential (
  web_application_target_t web_application_target)
{
  if (web_application_target == 0)
    return 0;

  return sql_int64_0_ps ("SELECT credential FROM web_application_targets"
                         " WHERE id = $1;",
                         SQL_RESOURCE_PARAM (web_application_target),
                         NULL);
}

/**
 * @brief Initialise a web application target task iterator.
 *
 * Iterates over all tasks that use the web application target.
 *
 * @param[in]  iterator                Iterator.
 * @param[in]  web_application_target  Web application target.
 */
void
init_web_application_target_task_iterator (
  iterator_t *iterator,
  web_application_target_t web_application_target)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (web_application_target);

  get.trash = 0;

  permissions = make_array ();
  array_add (permissions, g_strdup ("get_tasks"));

  available = acl_where_owned ("task",
                               &get,
                               1,
                               "any",
                               0,
                               permissions,
                               0,
                               &with_clause);

  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT name, uuid, %s FROM tasks"
                 " WHERE web_application_target = %llu"
                 " AND hidden = 0"
                 " ORDER BY name ASC;",
                 with_clause ? with_clause : "",
                 available,
                 web_application_target);

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the name from a web application target task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the task, or NULL if iteration is complete.
 */
DEF_ACCESS (web_application_target_task_iterator_name, 0);

/**
 * @brief Get the UUID from a web application target task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The UUID of the task, or NULL if iteration is complete.
 */
DEF_ACCESS (web_application_target_task_iterator_uuid, 1);

/**
 * @brief Get the read permission status from a web application target
 *        task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
web_application_target_task_iterator_readable (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, 2);
}

#endif /* ENABLE_WEB_APPLICATION_SCANNING */
